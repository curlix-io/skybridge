package agent

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/curlix-io/skybridge/internal/config"
	"github.com/curlix-io/skybridge/internal/wire/k8sapi"
)

// k8sCredentialExchangeTimeout mirrors credentialExchangeTimeout (credsource.go) — the control-plane
// round trip happens once per proxied HTTP request (not once per connection, since Kubernetes bearer
// auth has no persistent login step), so it must stay well under typical client request timeouts.
const k8sCredentialExchangeTimeout = 10 * time.Second

type k8sExchangeRequest struct {
	SessionToken string `json:"session_token"`
}

type k8sExchangeResponse struct {
	BearerToken        string `json:"bearer_token"`
	CACertPEM          string `json:"ca_cert_pem,omitempty"`
	InsecureSkipVerify bool   `json:"insecure_skip_verify,omitempty"`
	Error              string `json:"detail,omitempty"`
}

// NewHTTPK8sCredentialResolver builds a k8sapi.CredentialResolver that exchanges a client-presented
// session token for the real cluster bearer token via the control plane, mirroring
// NewHTTPCredentialResolver's shape (credsource.go) for the DB engines. Returns nil when the
// exchange URL is not configured — the caller then cannot serve Kubernetes targets at all (unlike
// DB engines there is no verbatim-passthrough fallback; see k8sapi's package doc).
func NewHTTPK8sCredentialResolver(cfg config.Agent) k8sapi.CredentialResolver {
	url := strings.TrimSpace(cfg.K8sCredentialExchangeURL)
	if url == "" {
		return nil
	}
	token := strings.TrimSpace(cfg.CredentialExchangeToken)
	client := &http.Client{Timeout: k8sCredentialExchangeTimeout}

	return func(ctx context.Context, sessionToken string) (k8sapi.UpstreamCredential, error) {
		if strings.TrimSpace(sessionToken) == "" {
			return k8sapi.UpstreamCredential{}, fmt.Errorf("no session token presented")
		}
		body, err := json.Marshal(k8sExchangeRequest{SessionToken: sessionToken})
		if err != nil {
			return k8sapi.UpstreamCredential{}, err
		}
		req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(body))
		if err != nil {
			return k8sapi.UpstreamCredential{}, err
		}
		req.Header.Set("Content-Type", "application/json")
		if token != "" {
			req.Header.Set("Authorization", "Bearer "+token)
		}
		resp, err := client.Do(req)
		if err != nil {
			return k8sapi.UpstreamCredential{}, fmt.Errorf("k8s credential exchange: %w", err)
		}
		defer resp.Body.Close()
		raw, _ := io.ReadAll(io.LimitReader(resp.Body, 16<<10))
		if resp.StatusCode < 200 || resp.StatusCode >= 300 {
			var er k8sExchangeResponse
			_ = json.Unmarshal(raw, &er)
			reason := strings.TrimSpace(er.Error)
			if reason == "" {
				reason = strings.TrimSpace(string(raw))
			}
			return k8sapi.UpstreamCredential{}, fmt.Errorf("k8s credential exchange rejected (%d): %s", resp.StatusCode, reason)
		}
		var out k8sExchangeResponse
		if err := json.Unmarshal(raw, &out); err != nil {
			return k8sapi.UpstreamCredential{}, fmt.Errorf("k8s credential exchange: bad response: %w", err)
		}
		if strings.TrimSpace(out.BearerToken) == "" {
			return k8sapi.UpstreamCredential{}, fmt.Errorf("k8s credential exchange returned no bearer token")
		}
		cred := k8sapi.UpstreamCredential{
			BearerToken:        out.BearerToken,
			InsecureSkipVerify: out.InsecureSkipVerify,
		}
		if out.CACertPEM != "" {
			cred.CACertPEM = []byte(out.CACertPEM)
		}
		return cred, nil
	}
}
