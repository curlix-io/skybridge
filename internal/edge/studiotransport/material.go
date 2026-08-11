//go:build querystudio

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
	studiov1 "github.com/curlix-io/skybridge/internal/genpb/curlix/studiogateway/v1"
)

const certRenewSkew = time.Hour

func (c *Client) ensureTLSMaterial(ctx context.Context) (*tlsMaterial, error) {
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
	if c.cfg.EnrollToken == "" {
		if stored != nil {
			return &tlsMaterial{caBundlePEM: pickCA(), clientCertPEM: stored.ClientCertPEM, clientKeyPEM: stored.ClientKeyPEM}, nil
		}
		return nil, errors.New("studio mTLS: no client cert and no SKYBRIDGE_STUDIO_ENROLLMENT_TOKEN")
	}
	m, err := c.enroll(ctx)
	if err != nil {
		return nil, err
	}
	_ = store.Save(ctx, &certstore.Material{CABundlePEM: m.caBundlePEM, ClientCertPEM: m.clientCertPEM, ClientKeyPEM: m.clientKeyPEM})
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

	c.logger.Info(fmt.Sprintf("studio enrolling tenant=%s agent=%s via %s", c.cfg.TenantID, c.cfg.AgentID, target))
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
