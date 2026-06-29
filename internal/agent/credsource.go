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
	"github.com/curlix-io/skybridge/internal/wire"
)

// credentialExchangeTimeout bounds the control-plane round trip done while a native client waits at
// the login prompt; it must be comfortably under common client login timeouts.
const credentialExchangeTimeout = 10 * time.Second

// exchangeRequest is the body the agent posts to the control plane to swap a client-presented session
// token for a freshly-minted upstream credential. The control plane authenticates the agent (bearer),
// validates the token, mints/looks up the credential via the broker, records the lease + attribution,
// and returns the credential. The agent never sees the user's identity beyond what it relays.
type exchangeRequest struct {
	SessionToken      string `json:"session_token"`
	RequestedUser     string `json:"requested_user,omitempty"`     // the "user" the native client asked for (informational)
	RequestedDatabase string `json:"requested_database,omitempty"` // the "database" the native client asked for
}

type exchangeResponse struct {
	Username string `json:"username"`
	Password string `json:"password"`
	Database string `json:"database,omitempty"`
	Error    string `json:"detail,omitempty"`
}

// NewHTTPCredentialResolver builds a wire.CredentialResolver that exchanges the client-presented
// session token for an upstream credential via the control plane. Returns nil when injection is not
// configured (the caller then uses the verbatim Proxy path).
func NewHTTPCredentialResolver(cfg config.Agent) wire.CredentialResolver {
	if !cfg.InjectCredentials || strings.TrimSpace(cfg.CredentialExchangeURL) == "" {
		return nil
	}
	url := strings.TrimSpace(cfg.CredentialExchangeURL)
	token := strings.TrimSpace(cfg.CredentialExchangeToken)
	client := &http.Client{Timeout: credentialExchangeTimeout}

	return func(ctx context.Context, startup map[string]string, secret string) (wire.UpstreamCredential, error) {
		if strings.TrimSpace(secret) == "" {
			return wire.UpstreamCredential{}, fmt.Errorf("no session token presented")
		}
		body, err := json.Marshal(exchangeRequest{
			SessionToken:      secret,
			RequestedUser:     startup["user"],
			RequestedDatabase: startup["database"],
		})
		if err != nil {
			return wire.UpstreamCredential{}, err
		}
		req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(body))
		if err != nil {
			return wire.UpstreamCredential{}, err
		}
		req.Header.Set("Content-Type", "application/json")
		if token != "" {
			req.Header.Set("Authorization", "Bearer "+token)
		}
		resp, err := client.Do(req)
		if err != nil {
			return wire.UpstreamCredential{}, fmt.Errorf("credential exchange: %w", err)
		}
		defer resp.Body.Close()
		raw, _ := io.ReadAll(io.LimitReader(resp.Body, 8<<10))
		if resp.StatusCode < 200 || resp.StatusCode >= 300 {
			// Surface the control plane's reason but keep it short; the engine maps this to a clean
			// auth failure shown to the native client.
			var er exchangeResponse
			_ = json.Unmarshal(raw, &er)
			reason := strings.TrimSpace(er.Error)
			if reason == "" {
				reason = strings.TrimSpace(string(raw))
			}
			return wire.UpstreamCredential{}, fmt.Errorf("credential exchange rejected (%d): %s", resp.StatusCode, reason)
		}
		var out exchangeResponse
		if err := json.Unmarshal(raw, &out); err != nil {
			return wire.UpstreamCredential{}, fmt.Errorf("credential exchange: bad response: %w", err)
		}
		if strings.TrimSpace(out.Username) == "" {
			return wire.UpstreamCredential{}, fmt.Errorf("credential exchange returned no username")
		}
		return wire.UpstreamCredential{
			Username: out.Username,
			Password: out.Password,
			Database: out.Database,
		}, nil
	}
}
