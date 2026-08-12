package agent

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/curlix-io/skybridge/internal/config"
	"github.com/curlix-io/skybridge/internal/mask"
)

const (
	recognizersFetchTimeout = 10 * time.Second
	recognizersMinPoll      = 15 * time.Second
)

// recognizersResponse mirrors the FastAPI SkybridgePiiRecognizersOut model
// (GET /api/v1/data-studio/studio/native-access/pii-recognizers).
type recognizersResponse struct {
	OrganizationID string   `json:"organization_id"`
	Recognizers    []any    `json:"recognizers"`
	Entities       []string `json:"entities"`
	ScoreThreshold float64  `json:"score_threshold"`
	Count          int      `json:"count"`
	GeneratedUnix  int64    `json:"generated_unix"`
}

// recognizersSource fetches the org's custom Presidio recognizers (plus the resolved entity
// allowlist and score threshold) from the control plane, scoped to this agent's driver +
// connection role — an org can define both org-wide and connection-scoped masking rules, and the
// backend resolves the applicable set per (driver, connection_role) pair. The backend only returns
// a non-empty list when the org has explicitly opted into delivery_mode='api_push' — an org left
// on the default 'manual' mode always gets an empty list here, so this poller never overrides a
// customer's own SSM/file-managed recognizers.
type recognizersSource struct {
	url            string
	token          string
	orgID          string
	driver         string
	connectionRole string
	client         *http.Client
}

func newRecognizersSource(cfg config.Agent) *recognizersSource {
	return &recognizersSource{
		url:            strings.TrimSpace(cfg.PIIRecognizersURL),
		token:          strings.TrimSpace(cfg.PIIRecognizersToken),
		orgID:          strings.TrimSpace(cfg.OrgID),
		driver:         strings.TrimSpace(cfg.DBType),
		connectionRole: strings.TrimSpace(cfg.ConnectionRole),
		client:         &http.Client{Timeout: recognizersFetchTimeout},
	}
}

// fetch returns the current ad-hoc recognizer definitions, entity allowlist, and score threshold
// resolved for the agent's organization + driver + connection role.
func (s *recognizersSource) fetch(ctx context.Context) (recognizersResponse, error) {
	reqURL, err := s.requestURL()
	if err != nil {
		return recognizersResponse{}, err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, reqURL, nil)
	if err != nil {
		return recognizersResponse{}, err
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
		return recognizersResponse{}, err
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		snippet, _ := io.ReadAll(io.LimitReader(resp.Body, 512))
		return recognizersResponse{}, fmt.Errorf("pii-recognizers %s -> %d: %s", s.url, resp.StatusCode, strings.TrimSpace(string(snippet)))
	}
	var out recognizersResponse
	if err := json.NewDecoder(io.LimitReader(resp.Body, 1<<20)).Decode(&out); err != nil {
		return recognizersResponse{}, fmt.Errorf("pii-recognizers decode: %w", err)
	}
	if out.Recognizers == nil {
		out.Recognizers = []any{}
	}
	return out, nil
}

// requestURL appends the driver/connection_role query params to s.url, using net/url so the
// values are properly escaped rather than string-concatenated.
func (s *recognizersSource) requestURL() (string, error) {
	u, err := url.Parse(s.url)
	if err != nil {
		return "", fmt.Errorf("pii-recognizers invalid url %q: %w", s.url, err)
	}
	q := u.Query()
	q.Set("driver", s.driver)
	q.Set("connection_role", s.connectionRole)
	u.RawQuery = q.Encode()
	return u.String(), nil
}

// startRecognizersSync seeds the remote masker's ad-hoc recognizers from the control plane and
// (when polling is enabled) keeps them refreshed in the background, hot-swapping in place. It is
// best-effort: a failed initial fetch leaves the static MaskRecognizersYAML/MaskRecognizersFile
// recognizers intact and logs the error. Returns immediately when no dynamic source is configured
// — orgs on the static SSM/file delivery path (PIIRecognizersURL unset) are unaffected.
func startRecognizersSync(ctx context.Context, cfg config.Agent, remote *mask.Remote, logger *slog.Logger) {
	if remote == nil || strings.TrimSpace(cfg.PIIRecognizersURL) == "" {
		return
	}
	if logger == nil {
		logger = slog.Default()
	}
	src := newRecognizersSource(cfg)

	refresh := func() bool {
		fctx, cancel := context.WithTimeout(ctx, recognizersFetchTimeout)
		defer cancel()
		resp, err := src.fetch(fctx)
		if err != nil {
			logger.Warn(fmt.Sprintf("pii-recognizers refresh failed: %v", err))
			return false
		}
		remote.ReplaceConfig(resp.Recognizers, resp.Entities, resp.ScoreThreshold)
		logger.Debug(fmt.Sprintf(
			"pii-recognizers synced (%d recognizers, %d entities, score_threshold=%v)",
			len(resp.Recognizers), len(resp.Entities), resp.ScoreThreshold,
		))
		return true
	}

	// Initial seed (synchronous so the first sessions get current recognizers when possible).
	refresh()

	if cfg.PIIRecognizersPollSeconds < 0 {
		return // fetch-once mode
	}
	interval := time.Duration(cfg.PIIRecognizersPollSeconds) * time.Second
	if interval < recognizersMinPoll {
		interval = recognizersMinPoll
	}
	go func() {
		defer recoverBackground(logger, "pii-recognizers sync")
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
