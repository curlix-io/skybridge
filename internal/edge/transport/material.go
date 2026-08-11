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
	connectorv1 "github.com/curlix-io/skybridge/internal/genpb/curlix/connector/v1"
)

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

	if c.cfg.EnrollToken == "" {
		if stored != nil {
			// Expired but no token to renew — try anyway; the gateway rejects if invalid.
			return &tlsMaterial{caBundlePEM: pickCA(), clientCertPEM: stored.ClientCertPEM, clientKeyPEM: stored.ClientKeyPEM}, nil
		}
		return nil, errors.New("mTLS configured (CA bundle present) but no client cert and no SKYBRIDGE_ENROLLMENT_TOKEN to enroll")
	}

	m, err := c.enroll(ctx)
	if err != nil {
		return nil, err
	}
	if err := store.Save(ctx, &certstore.Material{CABundlePEM: m.caBundlePEM, ClientCertPEM: m.clientCertPEM, ClientKeyPEM: m.clientKeyPEM}); err != nil {
		return nil, err
	}
	return m, nil
}

// enroll generates a fresh keypair + CSR and exchanges a one-time enrollment token for a signed cert
// over a server-TLS channel (no client cert yet).
func (c *Client) enroll(ctx context.Context) (*tlsMaterial, error) {
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
		EnrollmentToken: c.cfg.EnrollToken,
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
