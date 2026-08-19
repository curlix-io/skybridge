package studiotransport

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
	studiov1 "github.com/curlix-io/skybridge/internal/genpb/curlix/studiogateway/v1"
)

const certRenewSkew = time.Hour

// DefaultIamEnrollTokenPath mirrors internal/edge/transport.DefaultIamEnrollTokenPath — the
// control plane authenticates Studio's IAM-minted enroll-token requests the same way it does
// connector's.
const DefaultIamEnrollTokenPath = "/api/v1/skybridge/enrollments-iam"

func (c *Client) ensureTLSMaterial(ctx context.Context) (*tlsMaterial, error) {
	if c.cfg.ForceBearer {
		// SKYBRIDGE_CONNECTOR_KEY configured: intentionally stateless bearer-only mode. Never touch
		// certstore, even if CABundlePEM/TLSDir are also set — mirrors internal/edge/transport.
		return nil, nil
	}
	ca := c.cfg.CABundlePEM
	if len(ca) == 0 && c.cfg.TLSDir == "" {
		return nil, nil
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
		return nil, nil
	}
	enrollToken := c.cfg.EnrollToken
	if enrollToken == "" && c.cfg.IamAuthEnabled {
		// See internal/edge/transport's equivalent branch: mint a fresh enroll token from the
		// edge's ambient AWS identity instead of a static, single-use token, so a redeployed task
		// with a wiped disk can re-enroll without a human in the loop.
		token, ierr := edgeiam.EnrollTokenViaIAM(ctx, edgeiam.IamEnrollConfig{
			BaseURL:  c.cfg.IamEnrollURL,
			Path:     DefaultIamEnrollTokenPath,
			TenantID: c.cfg.TenantID,
			AgentID:  c.cfg.AgentID,
		})
		if ierr != nil {
			if stored != nil {
				return &tlsMaterial{caBundlePEM: pickCA(), clientCertPEM: stored.ClientCertPEM, clientKeyPEM: stored.ClientKeyPEM}, nil
			}
			return nil, fmt.Errorf("studio mTLS: IAM enroll-token: %w", ierr)
		}
		enrollToken = token
	}

	if enrollToken == "" {
		if stored != nil {
			return &tlsMaterial{caBundlePEM: pickCA(), clientCertPEM: stored.ClientCertPEM, clientKeyPEM: stored.ClientKeyPEM}, nil
		}
		return nil, errors.New("studio mTLS: no client cert and no SKYBRIDGE_STUDIO_ENROLLMENT_TOKEN")
	}
	m, err := c.enrollWithToken(ctx, enrollToken)
	if err != nil {
		return nil, err
	}
	_ = store.Save(ctx, &certstore.Material{CABundlePEM: m.caBundlePEM, ClientCertPEM: m.clientCertPEM, ClientKeyPEM: m.clientKeyPEM})
	return m, nil
}

func (c *Client) enroll(ctx context.Context) (*tlsMaterial, error) {
	return c.enrollWithToken(ctx, c.cfg.EnrollToken)
}

// enrollWithToken is enroll's implementation, parameterized on the token so ensureTLSMaterial can
// pass a freshly IAM-minted one without mutating c.cfg.
func (c *Client) enrollWithToken(ctx context.Context, enrollToken string) (*tlsMaterial, error) {
	keyPEM, csrPEM, err := generateKeyAndCSR(c.cfg.TrustDomain, c.cfg.TenantID, c.cfg.AgentID)
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

	c.logger.Info(fmt.Sprintf("studio enrolling tenant=%s agent=%s via %s", c.cfg.TenantID, c.cfg.AgentID, target))
	resp, err := studiov1.NewStudioGatewayClient(conn).Enroll(ctx, &studiov1.EnrollRequest{
		EnrollmentToken: enrollToken,
		TenantId:        c.cfg.TenantID,
		AgentId:         c.cfg.AgentID,
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
// identity on the mTLS channel -- mirrors internal/edge/transport's renewCert. No enrollment token
// is involved; the calling cert on the channel IS the identity proof.
func (c *Client) renewCert(ctx context.Context, current *tlsMaterial) (*tlsMaterial, error) {
	keyPEM, csrPEM, err := generateKeyAndCSR(c.cfg.TrustDomain, c.cfg.TenantID, c.cfg.AgentID)
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

	resp, err := studiov1.NewStudioGatewayClient(conn).Renew(ctx, &studiov1.RenewRequest{
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
	return "/var/lib/skybridge/studio-tls"
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
