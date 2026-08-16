package transport

import (
	"context"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"

	"github.com/curlix-io/skybridge/internal/certstore"
	"github.com/curlix-io/skybridge/internal/edgeiam"
	connectorv1 "github.com/curlix-io/skybridge/internal/genpb/curlix/connector/v1"
)

// DefaultIamEnrollTokenPath is used when Config.IamEnrollURL is set but no override path is given
// (there is currently no per-call override — every connector deployment hits the same path).
const DefaultIamEnrollTokenPath = "/api/v1/skybridge/enrollments-iam"

// tlsMaterial is the edge's mTLS identity: its client cert/key plus the CA bundle it trusts for the
// gateway. A nil *tlsMaterial means "bearer-token mode" (no CA configured).
type tlsMaterial struct {
	caBundlePEM   []byte
	clientCertPEM []byte
	clientKeyPEM  []byte
}

// certRenewSkew is how far ahead of expiry a cert is considered too stale to reuse (re-enroll).
const certRenewSkew = time.Hour

// ensureTLSMaterial loads valid mTLS material from the identity store, enrolling via the gateway
// if necessary. Returns (nil, nil) when no CA is configured, meaning the caller should use bearer
// mode.
func (c *Client) ensureTLSMaterial(ctx context.Context) (*tlsMaterial, error) {
	ca := c.cfg.CABundlePEM
	if len(ca) == 0 && c.cfg.TLSDir == "" {
		return nil, nil // no mTLS configured at all -> bearer
	}

	store := certstore.FromEnv(c.tlsDir(), c.cfg.IdentitySecretARN)
	stored, err := store.Load(ctx)
	if err != nil {
		return nil, err
	}

	pickCA := func() []byte {
		if stored != nil && len(stored.CABundlePEM) > 0 {
			return stored.CABundlePEM
		}
		return ca
	}

	if stored != nil && certValid(stored.ClientCertPEM, certRenewSkew) {
		return &tlsMaterial{caBundlePEM: pickCA(), clientCertPEM: stored.ClientCertPEM, clientKeyPEM: stored.ClientKeyPEM}, nil
	}

	if len(ca) == 0 {
		return nil, nil // no CA -> bearer (stored material may be stale/untrusted)
	}

	enrollToken := c.cfg.EnrollToken
	if enrollToken == "" && c.cfg.IamAuthEnabled {
		// No human-minted token needed: presign the edge's own ambient AWS identity (an ECS task
		// role, in production) and exchange it for a fresh, short-lived enroll token. Unlike a
		// static SKYBRIDGE_ENROLLMENT_TOKEN, this can be minted on every restart — including a
		// redeployed task with a wiped disk — so it never hits the "token already consumed by the
		// task I'm replacing" failure mode a single-use token has.
		token, ierr := edgeiam.EnrollTokenViaIAM(ctx, edgeiam.IamEnrollConfig{
			BaseURL:  c.cfg.IamEnrollURL,
			Path:     DefaultIamEnrollTokenPath,
			TenantID: c.cfg.TenantID,
			AgentID:  c.cfg.ConnectorID,
		})
		if ierr != nil {
			if stored != nil {
				// Mint failed (e.g. control plane hiccup) but we still have a stale-but-usable
				// cert cached — prefer that over hard-failing the connection attempt.
				return &tlsMaterial{caBundlePEM: pickCA(), clientCertPEM: stored.ClientCertPEM, clientKeyPEM: stored.ClientKeyPEM}, nil
			}
			return nil, fmt.Errorf("IAM enroll-token: %w", ierr)
		}
		enrollToken = token
	}

	if enrollToken == "" {
		if stored != nil {
			// Expired but no token to renew — try anyway; the gateway rejects if invalid.
			return &tlsMaterial{caBundlePEM: pickCA(), clientCertPEM: stored.ClientCertPEM, clientKeyPEM: stored.ClientKeyPEM}, nil
		}
		return nil, errors.New("mTLS configured (CA bundle present) but no client cert and no SKYBRIDGE_ENROLLMENT_TOKEN to enroll")
	}

	m, err := c.enrollWithToken(ctx, enrollToken)
	if err != nil {
		return nil, err
	}
	if err := store.Save(ctx, &certstore.Material{CABundlePEM: m.caBundlePEM, ClientCertPEM: m.clientCertPEM, ClientKeyPEM: m.clientKeyPEM}); err != nil {
		return nil, err
	}
	return m, nil
}

// enroll generates a fresh keypair + CSR and exchanges c.cfg.EnrollToken (a one-time enrollment
// token) for a signed cert over a server-TLS channel (no client cert yet).
func (c *Client) enroll(ctx context.Context) (*tlsMaterial, error) {
	return c.enrollWithToken(ctx, c.cfg.EnrollToken)
}

// enrollWithToken is enroll's implementation, parameterized on the token so ensureTLSMaterial can
// pass a freshly IAM-minted one without mutating c.cfg.
func (c *Client) enrollWithToken(ctx context.Context, enrollToken string) (*tlsMaterial, error) {
	keyPEM, csrPEM, err := generateKeyAndCSR(c.cfg.TrustDomain, c.cfg.TenantID, c.cfg.ConnectorID)
	if err != nil {
		return nil, err
	}
	tlsCfg, err := serverTLSConfig(c.cfg.CABundlePEM)
	if err != nil {
		return nil, err
	}
	target := c.cfg.EnrollTarget
	if target == "" {
		target = c.cfg.Target
	}
	conn, err := grpc.NewClient(target, grpc.WithTransportCredentials(credentials.NewTLS(tlsCfg)))
	if err != nil {
		return nil, err
	}
	defer conn.Close()

	c.logger.Info(fmt.Sprintf("enrolling tenant=%s edge=%s via %s", c.cfg.TenantID, c.cfg.ConnectorID, target))
	resp, err := connectorv1.NewConnectorGatewayClient(conn).Enroll(ctx, &connectorv1.EnrollRequest{
		EnrollmentToken: enrollToken,
		TenantId:        c.cfg.TenantID,
		ConnectorId:     c.cfg.ConnectorID,
		CsrPem:          string(csrPEM),
	})
	if err != nil {
		return nil, err
	}
	caOut := []byte(resp.GetCaBundlePem())
	if len(caOut) == 0 {
		caOut = c.cfg.CABundlePEM
	}
	return &tlsMaterial{
		caBundlePEM:   caOut,
		clientCertPEM: []byte(resp.GetClientCertPem()),
		clientKeyPEM:  keyPEM,
	}, nil
}

// renewCert proactively refreshes the client cert using the CURRENT still-valid cert as proof of
// identity on the mTLS channel -- unlike enroll, no enrollment token is involved. Persists the
// result via the same certstore used by ensureTLSMaterial so a later restart picks up the renewed
// cert instead of the one it replaced.
func (c *Client) renewCert(ctx context.Context, current *tlsMaterial) (*tlsMaterial, error) {
	keyPEM, csrPEM, err := generateKeyAndCSR(c.cfg.TrustDomain, c.cfg.TenantID, c.cfg.ConnectorID)
	if err != nil {
		return nil, err
	}
	tlsCfg, err := mtlsTLSConfig(current)
	if err != nil {
		return nil, err
	}
	conn, err := grpc.NewClient(c.cfg.Target, grpc.WithTransportCredentials(credentials.NewTLS(tlsCfg)))
	if err != nil {
		return nil, err
	}
	defer conn.Close()

	resp, err := connectorv1.NewConnectorGatewayClient(conn).Renew(ctx, &connectorv1.RenewRequest{
		CsrPem: string(csrPEM),
	})
	if err != nil {
		return nil, err
	}
	caOut := []byte(resp.GetCaBundlePem())
	if len(caOut) == 0 {
		caOut = current.caBundlePEM
	}
	m := &tlsMaterial{
		caBundlePEM:   caOut,
		clientCertPEM: []byte(resp.GetClientCertPem()),
		clientKeyPEM:  keyPEM,
	}
	store := certstore.FromEnv(c.tlsDir(), c.cfg.IdentitySecretARN)
	if err := store.Save(ctx, &certstore.Material{CABundlePEM: m.caBundlePEM, ClientCertPEM: m.clientCertPEM, ClientKeyPEM: m.clientKeyPEM}); err != nil {
		return nil, err
	}
	return m, nil
}

func (c *Client) tlsDir() string {
	if c.cfg.TLSDir != "" {
		return c.cfg.TLSDir
	}
	return "/var/lib/skybridge/tls"
}

func certValid(certPEM []byte, skew time.Duration) bool {
	block, _ := pem.Decode(certPEM)
	if block == nil {
		return false
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return false
	}
	return time.Now().Add(skew).Before(cert.NotAfter)
}
