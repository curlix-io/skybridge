package studiotransport

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

	studiov1 "github.com/curlix-io/skybridge/internal/genpb/curlix/studiogateway/v1"
)

const certRenewSkew = time.Hour

func (c *Client) ensureTLSMaterial(ctx context.Context) (*tlsMaterial, error) {
	ca := c.cfg.CABundlePEM
	if len(ca) == 0 && c.cfg.TLSDir == "" {
		return nil, nil
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
		return nil, nil
	}
	if c.cfg.EnrollToken == "" {
		if len(cert) > 0 && len(key) > 0 {
			return &tlsMaterial{caBundlePEM: pickCA(), clientCertPEM: cert, clientKeyPEM: key}, nil
		}
		return nil, errors.New("studio mTLS: no client cert and no SKYBRIDGE_STUDIO_ENROLLMENT_TOKEN")
	}
	m, err := c.enroll(ctx)
	if err != nil {
		return nil, err
	}
	_ = writeSecret(caPath, m.caBundlePEM, 0o644)
	_ = writeSecret(certPath, m.clientCertPEM, 0o644)
	_ = writeSecret(keyPath, m.clientKeyPEM, 0o600)
	return m, nil
}

func (c *Client) enroll(ctx context.Context) (*tlsMaterial, error) {
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

	c.logger.Printf("skybridge-edge: studio enrolling tenant=%s agent=%s via %s", c.cfg.TenantID, c.cfg.AgentID, target)
	resp, err := studiov1.NewStudioGatewayClient(conn).Enroll(ctx, &studiov1.EnrollRequest{
		EnrollmentToken: c.cfg.EnrollToken,
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

func (c *Client) tlsPaths() (caPath, certPath, keyPath string) {
	dir := c.cfg.TLSDir
	if dir == "" {
		dir = "/var/lib/skybridge/studio-tls"
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
