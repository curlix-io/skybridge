package transport

import (
	"context"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"os"
	"path/filepath"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"

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

// ensureTLSMaterial loads valid mTLS material from disk, enrolling via the gateway if necessary.
// Returns (nil, nil) when no CA is configured, meaning the caller should use bearer mode.
func (c *Client) ensureTLSMaterial(ctx context.Context) (*tlsMaterial, error) {
	ca := c.cfg.CABundlePEM
	if len(ca) == 0 && c.cfg.TLSDir == "" {
		return nil, nil // no mTLS configured at all -> bearer
	}

	caPath, certPath, keyPath := c.tlsPaths()
	storedCA := readFileOrNil(caPath)
	cert := readFileOrNil(certPath)
	key := readFileOrNil(keyPath)

	pickCA := func() []byte {
		if len(storedCA) > 0 {
			return storedCA
		}
		return ca
	}

	if len(cert) > 0 && len(key) > 0 && certValid(cert, certRenewSkew) {
		return &tlsMaterial{caBundlePEM: pickCA(), clientCertPEM: cert, clientKeyPEM: key}, nil
	}

	if len(ca) == 0 {
		return nil, nil // no CA -> bearer (disk may hold a stale cert we can't trust)
	}

	if c.cfg.EnrollToken == "" {
		if len(cert) > 0 && len(key) > 0 {
			// Expired but no token to renew — try anyway; the gateway rejects if invalid.
			return &tlsMaterial{caBundlePEM: pickCA(), clientCertPEM: cert, clientKeyPEM: key}, nil
		}
		return nil, errors.New("mTLS configured (CA bundle present) but no client cert and no SKYBRIDGE_ENROLLMENT_TOKEN to enroll")
	}

	m, err := c.enroll(ctx)
	if err != nil {
		return nil, err
	}
	if err := writeSecret(caPath, m.caBundlePEM, 0o644); err != nil {
		return nil, err
	}
	if err := writeSecret(certPath, m.clientCertPEM, 0o644); err != nil {
		return nil, err
	}
	if err := writeSecret(keyPath, m.clientKeyPEM, 0o600); err != nil {
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

	c.logger.Printf("enrolling tenant=%s edge=%s via %s", c.cfg.TenantID, c.cfg.ConnectorID, target)
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

func (c *Client) tlsPaths() (caPath, certPath, keyPath string) {
	dir := c.cfg.TLSDir
	if dir == "" {
		dir = "/var/lib/skybridge/tls"
	}
	return filepath.Join(dir, "ca.pem"), filepath.Join(dir, "client.crt"), filepath.Join(dir, "client.key")
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

func readFileOrNil(path string) []byte {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil
	}
	return b
}

func writeSecret(path string, data []byte, mode os.FileMode) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}
	return os.WriteFile(path, data, mode)
}
