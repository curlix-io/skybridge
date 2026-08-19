package gateway

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"strings"
)

// AgentAuthVerifier verifies an agent's bearer token (SKYBRIDGE_CONNECTOR_KEY, presented on
// tunnel.Control.Token when the connection has no verified mTLS client certificate — see
// internal/agent/agent.go's RunTunnel) and returns the identity it's bound to. ok is false for an
// unknown, expired, or empty token — ServeAgent rejects registration in that case, same as an
// unverified mTLS connection.
type AgentAuthVerifier interface {
	Verify(ctx context.Context, token string) (tenantID, agentID string, ok bool)
}

// NoopAgentAuthVerifier is used when no control plane is configured. Like NoopTargetResolver
// (and unlike NoopWireAdmitter's safe "allow" default), there is no safe default identity for an
// unverified bearer token — it always fails closed.
type NoopAgentAuthVerifier struct{}

// Verify implements AgentAuthVerifier.
func (NoopAgentAuthVerifier) Verify(context.Context, string) (string, string, bool) {
	return "", "", false
}

// DefaultAgentAuthVerifyPath is used when NewHTTPAgentAuthVerifier is given an empty basePath.
const DefaultAgentAuthVerifyPath = "/api/v1/studio/native-access/verify-agent-token"

// HTTPAgentAuthVerifier calls the control plane to verify an agent bearer token, per registration
// attempt (no local cache — tokens can be revoked between calls).
type HTTPAgentAuthVerifier struct {
	baseURL  string
	basePath string
	token    string
	client   *http.Client
}

// NewHTTPAgentAuthVerifier builds a verifier. baseURL is the control-plane origin; basePath
// defaults to DefaultAgentAuthVerifyPath. token is the gateway's own service bearer (the same
// credential HTTPTargetResolver presents), not the agent's token being verified.
func NewHTTPAgentAuthVerifier(baseURL, basePath, token string) *HTTPAgentAuthVerifier {
	bp := strings.TrimRight(strings.TrimSpace(basePath), "/")
	if bp == "" {
		bp = DefaultAgentAuthVerifyPath
	}
	return &HTTPAgentAuthVerifier{
		baseURL:  strings.TrimRight(baseURL, "/"),
		basePath: bp,
		token:    token,
		client:   &http.Client{Timeout: storeTimeout},
	}
}

type verifyAgentTokenBody struct {
	Token string `json:"token"`
}

type verifyAgentTokenResponse struct {
	OK             bool   `json:"ok"`
	OrganizationID string `json:"organization_id"`
	ConnectorID    string `json:"connector_id"`
}

// Verify implements AgentAuthVerifier by POSTing {"token": token} to the control plane and
// mapping its {ok, organization_id, connector_id} response. Any transport/decode error or a
// non-2xx status is treated as unverified (fail closed), not surfaced as a distinct error — the
// caller (ServeAgent) only needs to know whether to trust this connection, not why not.
func (h *HTTPAgentAuthVerifier) Verify(ctx context.Context, token string) (tenantID, agentID string, ok bool) {
	token = strings.TrimSpace(token)
	if token == "" {
		return "", "", false
	}
	body, err := json.Marshal(verifyAgentTokenBody{Token: token})
	if err != nil {
		return "", "", false
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, h.baseURL+h.basePath, strings.NewReader(string(body)))
	if err != nil {
		return "", "", false
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")
	if h.token != "" {
		req.Header.Set("Authorization", "Bearer "+h.token)
	}
	resp, err := h.client.Do(req)
	if err != nil {
		return "", "", false
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 512))
		return "", "", false
	}
	var out verifyAgentTokenResponse
	if err := json.NewDecoder(io.LimitReader(resp.Body, 1<<16)).Decode(&out); err != nil {
		return "", "", false
	}
	if !out.OK || strings.TrimSpace(out.OrganizationID) == "" {
		return "", "", false
	}
	return out.OrganizationID, out.ConnectorID, true
}
