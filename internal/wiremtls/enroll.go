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
)

// CertRenewSkew is how far ahead of expiry a cert is considered too stale to reuse (re-enroll).
const CertRenewSkew = time.Hour

const enrollTimeout = 15 * time.Second

// EnrollConfig configures the HTTP enroll bootstrap call. EnrollURL is the control-plane origin +
// path (defaults to ".../api/v1/skybridge/wire-mtls/enroll" when Path is empty).
type EnrollConfig struct {
	BaseURL     string // control-plane origin, e.g. https://app.curlix.io
	Path        string // defaults to DefaultEnrollPath
	TenantID    string
	AgentID     string
	EnrollToken string // one-time token minted by an admin via wire-mtls/enroll-token
	TrustDomain string
	TLSDir      string // directory holding/persisting ca.pem, client.crt, client.key
	CABundlePEM []byte // optional: pin the CA used for the enroll call itself (server-TLS only)
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
	caPath, certPath, keyPath := tlsPaths(cfg.TLSDir)
	storedCA := readFileOrNil(caPath)
	cert := readFileOrNil(certPath)
	key := readFileOrNil(keyPath)

	pickCA := func() []byte {
		if len(storedCA) > 0 {
			return storedCA
		}
		return cfg.CABundlePEM
	}

	if len(cert) > 0 && len(key) > 0 && CertValid(cert, CertRenewSkew) {
		return &Material{CABundlePEM: pickCA(), ClientCertPEM: cert, ClientKeyPEM: key}, nil
	}

	if cfg.EnrollToken == "" {
		if len(cert) > 0 && len(key) > 0 {
			// Expired but no token to renew — try anyway; the gateway rejects if invalid.
			return &Material{CABundlePEM: pickCA(), ClientCertPEM: cert, ClientKeyPEM: key}, nil
		}
		return nil, nil // no cert, no token -> caller falls back to bearer-token tunnel mode
	}

	m, err := enroll(ctx, cfg)
	if err != nil {
		return nil, err
	}
	if err := writeSecret(caPath, m.CABundlePEM, 0o644); err != nil {
		return nil, err
	}
	if err := writeSecret(certPath, m.ClientCertPEM, 0o644); err != nil {
		return nil, err
	}
	if err := writeSecret(keyPath, m.ClientKeyPEM, 0o600); err != nil {
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

func tlsPaths(dir string) (caPath, certPath, keyPath string) {
	if dir == "" {
		dir = "/var/lib/skybridge/wire-tls"
	}
	return filepath.Join(dir, "ca.pem"), filepath.Join(dir, "client.crt"), filepath.Join(dir, "client.key")
}

func readFileOrNil(path string) []byte {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil
	}
	return b
}

func writeSecret(path string, data []byte, mode os.FileMode) error {
	if len(data) == 0 {
		return nil
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}
	return os.WriteFile(path, data, mode)
}
