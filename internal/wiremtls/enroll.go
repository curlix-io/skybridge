package wiremtls

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/curlix-io/skybridge/internal/certstore"
)

// CertRenewSkew is how far ahead of expiry a cert is considered too stale to reuse (re-enroll).
const CertRenewSkew = time.Hour

const enrollTimeout = 15 * time.Second

// EnrollConfig configures the HTTP enroll bootstrap call. EnrollURL is the control-plane origin +
// path (defaults to ".../api/v1/skybridge/wire-mtls/enroll" when Path is empty).
type EnrollConfig struct {
	BaseURL     string // control-plane origin, e.g. https://app.example.com
	Path        string // defaults to DefaultEnrollPath
	TenantID    string
	AgentID     string
	EnrollToken string // one-time token minted by an admin via wire-mtls/enroll-token
	TrustDomain string
	TLSDir      string // directory holding/persisting ca.pem, client.crt, client.key
	CABundlePEM []byte // optional: pin the CA used for the enroll call itself (server-TLS only)
	// IdentitySecretARN, when set, mirrors the issued cert to this AWS Secrets Manager secret so a
	// replaced task (fresh disk) recovers its identity instead of re-enrolling with an already-used
	// one-time token. See SKYBRIDGE_WIRE_MTLS_IDENTITY_SECRET_ARN.
	IdentitySecretARN string
}

// DefaultEnrollPath is used when EnrollConfig.Path is empty.
const DefaultEnrollPath = "/api/v1/skybridge/wire-mtls/enroll"

type enrollRequestBody struct {
	EnrollToken string `json:"enroll_token"`
	TenantID    string `json:"tenant_id"`
	AgentID     string `json:"agent_id"`
	CsrPem      string `json:"csr_pem"`
}

type enrollResponseBody struct {
	ClientCertPEM string `json:"client_cert_pem"`
	CABundlePEM   string `json:"ca_bundle_pem"`
	Detail        string `json:"detail"`
}

// EnsureMaterial loads valid mTLS material from disk, enrolling via HTTP if necessary. Returns
// (nil, nil) when no CA bundle is configured for the enroll call itself AND no cert is cached — the
// caller should then fall back to the legacy bearer-token tunnel mode.
func EnsureMaterial(ctx context.Context, cfg EnrollConfig) (*Material, error) {
	store := certstore.FromEnv(tlsDir(cfg.TLSDir), cfg.IdentitySecretARN)
	stored, err := store.Load(ctx)
	if err != nil {
		return nil, err
	}

	pickCA := func() []byte {
		if stored != nil && len(stored.CABundlePEM) > 0 {
			return stored.CABundlePEM
		}
		return cfg.CABundlePEM
	}

	if stored != nil && CertValid(stored.ClientCertPEM, CertRenewSkew) {
		return &Material{CABundlePEM: pickCA(), ClientCertPEM: stored.ClientCertPEM, ClientKeyPEM: stored.ClientKeyPEM}, nil
	}

	if cfg.EnrollToken == "" {
		if stored != nil {
			// Expired but no token to renew — try anyway; the gateway rejects if invalid.
			return &Material{CABundlePEM: pickCA(), ClientCertPEM: stored.ClientCertPEM, ClientKeyPEM: stored.ClientKeyPEM}, nil
		}
		return nil, nil // no cert, no token -> caller falls back to bearer-token tunnel mode
	}

	m, err := enroll(ctx, cfg)
	if err != nil {
		return nil, err
	}
	if err := store.Save(ctx, &certstore.Material{CABundlePEM: m.CABundlePEM, ClientCertPEM: m.ClientCertPEM, ClientKeyPEM: m.ClientKeyPEM}); err != nil {
		return nil, err
	}
	return m, nil
}

func enroll(ctx context.Context, cfg EnrollConfig) (*Material, error) {
	keyPEM, csrPEM, err := GenerateKeyAndCSR(cfg.TrustDomain, cfg.TenantID, cfg.AgentID)
	if err != nil {
		return nil, err
	}
	tlsCfg, err := ServerTLSConfig(cfg.CABundlePEM)
	if err != nil {
		return nil, err
	}
	path := strings.TrimSpace(cfg.Path)
	if path == "" {
		path = DefaultEnrollPath
	}
	url := strings.TrimRight(strings.TrimSpace(cfg.BaseURL), "/") + path

	body, err := json.Marshal(enrollRequestBody{
		EnrollToken: cfg.EnrollToken,
		TenantID:    cfg.TenantID,
		AgentID:     cfg.AgentID,
		CsrPem:      string(csrPEM),
	})
	if err != nil {
		return nil, err
	}

	client := &http.Client{
		Timeout:   enrollTimeout,
		Transport: &http.Transport{TLSClientConfig: tlsCfg},
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("wire mTLS enroll: %w", err)
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	var out enrollResponseBody
	_ = json.Unmarshal(raw, &out)
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		detail := strings.TrimSpace(out.Detail)
		if detail == "" {
			detail = strings.TrimSpace(string(raw))
		}
		return nil, fmt.Errorf("wire mTLS enroll rejected (%d): %s", resp.StatusCode, detail)
	}

	caOut := []byte(out.CABundlePEM)
	if len(caOut) == 0 {
		caOut = cfg.CABundlePEM
	}
	return &Material{
		CABundlePEM:   caOut,
		ClientCertPEM: []byte(out.ClientCertPEM),
		ClientKeyPEM:  keyPEM,
	}, nil
}

func tlsDir(dir string) string {
	if dir == "" {
		// /var/lib isn't writable by the distroless "nonroot" image's default user; /tmp always is
		// (standard Linux world-writable + sticky bit). On Fargate this local cache is ephemeral
		// anyway — IdentitySecretARN (certstore) or IAM/enroll-token re-enrollment covers surviving
		// a task restart.
		return filepath.Join(os.TempDir(), "skybridge", "wire-tls")
	}
	return dir
}
