package agent

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"strings"
	"time"

	"github.com/curlix-io/skybridge/internal/config"
	"github.com/curlix-io/skybridge/internal/mask"
)

const (
	overlayFetchTimeout = 10 * time.Second
	overlayMinPoll      = 15 * time.Second
)

// overlayResponse is the control-plane projection of the org PII schema. It mirrors the FastAPI
// SkybridgePiiOverlayOut model (GET /api/v1/data-studio/studio/native-access/pii-overlay).
type overlayResponse struct {
	OrganizationID string            `json:"organization_id"`
	Columns        map[string]string `json:"columns"`
	Count          int               `json:"count"`
	GeneratedUnix  int64             `json:"generated_unix"`
}

// overlaySource fetches the projected column->token overlay from the control plane.
type overlaySource struct {
	url    string
	token  string
	orgID  string
	client *http.Client
}

func newOverlaySource(cfg config.Agent) *overlaySource {
	return &overlaySource{
		url:    strings.TrimSpace(cfg.PIIOverlayURL),
		token:  strings.TrimSpace(cfg.PIIOverlayToken),
		orgID:  strings.TrimSpace(cfg.OrgID),
		client: &http.Client{Timeout: overlayFetchTimeout},
	}
}

// fetch returns the current column->token rules for the agent's organization.
func (s *overlaySource) fetch(ctx context.Context) (map[string]string, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, s.url, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept", "application/json")
	if s.token != "" {
		req.Header.Set("Authorization", "Bearer "+s.token)
	}
	if s.orgID != "" {
		req.Header.Set("X-Curlix-Organization-Id", s.orgID)
	}
	resp, err := s.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		snippet, _ := io.ReadAll(io.LimitReader(resp.Body, 512))
		return nil, fmt.Errorf("pii-overlay %s -> %d: %s", s.url, resp.StatusCode, strings.TrimSpace(string(snippet)))
	}
	var out overlayResponse
	if err := json.NewDecoder(io.LimitReader(resp.Body, 1<<20)).Decode(&out); err != nil {
		return nil, fmt.Errorf("pii-overlay decode: %w", err)
	}
	if out.Columns == nil {
		out.Columns = map[string]string{}
	}
	return out.Columns, nil
}

// startOverlaySync seeds the overlay from the control plane and (when polling is enabled) keeps it
// refreshed in the background, hot-swapping rules in place. It is best-effort: a failed initial
// fetch leaves the static SKYBRIDGE_PII_OVERLAY rules intact and logs the error. Returns immediately
// when no dynamic source is configured.
func startOverlaySync(ctx context.Context, cfg config.Agent, overlay *mask.Overlay, logger *log.Logger) {
	if overlay == nil || strings.TrimSpace(cfg.PIIOverlayURL) == "" {
		return
	}
	if logger == nil {
		logger = log.Default()
	}
	src := newOverlaySource(cfg)

	refresh := func() bool {
		fctx, cancel := context.WithTimeout(ctx, overlayFetchTimeout)
		defer cancel()
		rules, err := src.fetch(fctx)
		if err != nil {
			logger.Printf("skybridge-agent: pii-overlay refresh failed: %v", err)
			return false
		}
		overlay.Replace(rules)
		logger.Printf("skybridge-agent: pii-overlay synced (%d columns)", len(rules))
		return true
	}

	// Initial seed (synchronous so the first sessions get current rules when possible).
	refresh()

	if cfg.PIIOverlayPollSeconds < 0 {
		return // fetch-once mode
	}
	interval := time.Duration(cfg.PIIOverlayPollSeconds) * time.Second
	if interval < overlayMinPoll {
		interval = overlayMinPoll
	}
	go func() {
		t := time.NewTicker(interval)
		defer t.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-t.C:
				refresh()
			}
		}
	}()
}
