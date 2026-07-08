package gateway

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
)

// WireAdmitter checks whether a native client IP is permitted for an organization before the wire
// handshake is relayed. The control plane enforces the same Allowed tenant IPs list as HTTP /api/v1.
type WireAdmitter interface {
	Admit(ctx context.Context, orgID, clientIP, target string) error
}

// NoopWireAdmitter allows all clients (default when no control plane is configured).
type NoopWireAdmitter struct{}

// Admit implements WireAdmitter.
func (NoopWireAdmitter) Admit(context.Context, string, string, string) error { return nil }

// DefaultWireAdmitPath is used when NewHTTPWireAdmitter is given an empty basePath.
const DefaultWireAdmitPath = "/api/v1/data-studio/studio/native-access/wire-admit"

// HTTPWireAdmitter calls the control plane wire-admit route before relaying a native client.
type HTTPWireAdmitter struct {
	baseURL  string
	basePath string
	token    string
	client   *http.Client
}

// NewHTTPWireAdmitter builds an admitter. baseURL is the control-plane origin; basePath defaults to
// DefaultWireAdmitPath.
func NewHTTPWireAdmitter(baseURL, basePath, token string) *HTTPWireAdmitter {
	bp := strings.TrimRight(strings.TrimSpace(basePath), "/")
	if bp == "" {
		bp = DefaultWireAdmitPath
	}
	return &HTTPWireAdmitter{
		baseURL:  strings.TrimRight(baseURL, "/"),
		basePath: bp,
		token:    token,
		client:   &http.Client{Timeout: storeTimeout},
	}
}

type wireAdmitRequest struct {
	OrganizationID string `json:"organization_id"`
	ClientIP       string `json:"client_ip"`
	Target         string `json:"target,omitempty"`
}

type wireAdmitError struct {
	Detail string `json:"detail"`
}

// Admit implements WireAdmitter.
func (h *HTTPWireAdmitter) Admit(ctx context.Context, orgID, clientIP, target string) error {
	orgID = strings.TrimSpace(orgID)
	if orgID == "" {
		return nil
	}
	ip := HostFromTCPAddr(clientIP)
	if ip == "" {
		return fmt.Errorf("wire admit: missing client IP")
	}
	body, err := json.Marshal(wireAdmitRequest{
		OrganizationID: orgID,
		ClientIP:       ip,
		Target:         strings.TrimSpace(target),
	})
	if err != nil {
		return err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, h.baseURL+h.basePath, bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	if h.token != "" {
		req.Header.Set("Authorization", "Bearer "+h.token)
	}
	resp, err := h.client.Do(req)
	if err != nil {
		return fmt.Errorf("wire admit: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 200 && resp.StatusCode < 300 {
		return nil
	}
	raw, _ := io.ReadAll(io.LimitReader(resp.Body, 512))
	var er wireAdmitError
	_ = json.Unmarshal(raw, &er)
	reason := strings.TrimSpace(er.Detail)
	if reason == "" {
		reason = strings.TrimSpace(string(raw))
	}
	return fmt.Errorf("wire admit rejected (%d): %s", resp.StatusCode, reason)
}

// HostFromTCPAddr extracts the host from net.TCPAddr.String() forms (host:port or [ipv6]:port).
func HostFromTCPAddr(addr string) string {
	raw := strings.TrimSpace(addr)
	if raw == "" {
		return ""
	}
	if strings.HasPrefix(raw, "[") {
		if host, _, err := net.SplitHostPort(raw); err == nil {
			return host
		}
	}
	if host, _, err := net.SplitHostPort(raw); err == nil {
		return host
	}
	return raw
}
