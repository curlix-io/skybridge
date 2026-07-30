package gateway

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"

	"github.com/curlix-io/skybridge/internal/tunnel"
)

// TargetResolver resolves a target name to dial/attribution info for one client connection, live —
// no caching. The gateway calls this on every ServeClient/Open, resolving addr/db_type per
// connection instead of the agent announcing a static target list at registration.
type TargetResolver interface {
	Resolve(ctx context.Context, orgID, target string) (tunnel.Target, error)
}

// ErrTargetNotFound is returned when the control plane has no resolvable binding for the target.
var ErrTargetNotFound = errors.New("gateway: target not found")

// NoopTargetResolver is used when no control plane is configured. Unlike NoopWireAdmitter (which
// safely defaults to "allow"), target resolution has no safe default other than failing closed —
// there is nothing to relay to without a resolved addr.
type NoopTargetResolver struct{}

// Resolve implements TargetResolver.
func (NoopTargetResolver) Resolve(context.Context, string, string) (tunnel.Target, error) {
	return tunnel.Target{}, ErrTargetNotFound
}

// DefaultWireTargetPath is used when NewHTTPTargetResolver is given an empty basePath.
const DefaultWireTargetPath = "/api/v1/data-studio/studio/native-access/wire-targets"

// HTTPTargetResolver calls the control plane wire-targets route to resolve one target, per
// connection (no local cache).
type HTTPTargetResolver struct {
	baseURL  string
	basePath string
	token    string
	client   *http.Client
}

// NewHTTPTargetResolver builds a resolver. baseURL is the control-plane origin; basePath defaults to
// DefaultWireTargetPath.
func NewHTTPTargetResolver(baseURL, basePath, token string) *HTTPTargetResolver {
	bp := strings.TrimRight(strings.TrimSpace(basePath), "/")
	if bp == "" {
		bp = DefaultWireTargetPath
	}
	return &HTTPTargetResolver{
		baseURL:  strings.TrimRight(baseURL, "/"),
		basePath: bp,
		token:    token,
		client:   &http.Client{Timeout: storeTimeout},
	}
}

type wireTargetOut struct {
	Name           string `json:"name"`
	Addr           string `json:"addr"`
	DBType         string `json:"db_type"`
	ResourceRoleID string `json:"resource_role_id"`
}

type wireTargetsResponse struct {
	OrganizationID string          `json:"organization_id"`
	Targets        []wireTargetOut `json:"targets"`
}

// Resolve implements TargetResolver by GETting wire-targets?organization_id=&target_name=<target>
// and mapping the single-element response.
func (h *HTTPTargetResolver) Resolve(ctx context.Context, orgID, target string) (tunnel.Target, error) {
	orgID = strings.TrimSpace(orgID)
	target = strings.TrimSpace(target)
	if orgID == "" || target == "" {
		return tunnel.Target{}, fmt.Errorf("target resolve: missing organization_id or target")
	}
	u, err := url.Parse(h.baseURL + h.basePath)
	if err != nil {
		return tunnel.Target{}, err
	}
	q := u.Query()
	q.Set("organization_id", orgID)
	q.Set("target_name", target)
	u.RawQuery = q.Encode()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u.String(), nil)
	if err != nil {
		return tunnel.Target{}, err
	}
	req.Header.Set("Accept", "application/json")
	if h.token != "" {
		req.Header.Set("Authorization", "Bearer "+h.token)
	}
	resp, err := h.client.Do(req)
	if err != nil {
		return tunnel.Target{}, fmt.Errorf("target resolve: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusNotFound {
		return tunnel.Target{}, ErrTargetNotFound
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		raw, _ := io.ReadAll(io.LimitReader(resp.Body, 512))
		return tunnel.Target{}, fmt.Errorf("target resolve (%d): %s", resp.StatusCode, strings.TrimSpace(string(raw)))
	}
	var out wireTargetsResponse
	if err := json.NewDecoder(io.LimitReader(resp.Body, 1<<16)).Decode(&out); err != nil {
		return tunnel.Target{}, fmt.Errorf("target resolve decode: %w", err)
	}
	if len(out.Targets) == 0 {
		return tunnel.Target{}, ErrTargetNotFound
	}
	t := out.Targets[0]
	return tunnel.Target{
		Name:           t.Name,
		Addr:           t.Addr,
		DBType:         strings.ToLower(t.DBType),
		ResourceRoleID: t.ResourceRoleID,
	}, nil
}
