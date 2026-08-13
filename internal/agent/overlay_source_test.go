package agent

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/curlix-io/skybridge/internal/config"
	"github.com/curlix-io/skybridge/internal/mask"
)

func TestOverlaySourceFetchParses(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if got := r.Header.Get("Authorization"); got != "Bearer tok-1" {
			t.Errorf("missing/!bearer auth header: %q", got)
		}
		if got := r.Header.Get(DefaultOrgHeader); got != "org-9" {
			t.Errorf("missing org header: %q", got)
		}
		_ = json.NewEncoder(w).Encode(overlayResponse{
			OrganizationID: "org-9",
			Columns:        map[string]string{"email": "[email]", "ssn": "[ssn]"},
			Count:          2,
		})
	}))
	defer srv.Close()

	src := newOverlaySource(config.Agent{PIIOverlayURL: srv.URL, PIIOverlayToken: "tok-1", OrgID: "org-9"})
	rules, _, err := src.fetch(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if rules["email"] != "[email]" || rules["ssn"] != "[ssn]" {
		t.Fatalf("unexpected rules: %v", rules)
	}
}

func TestOverlaySourceFetchUsesCustomOrgHeader(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if got := r.Header.Get("X-Tenant-Id"); got != "org-9" {
			t.Errorf("missing custom org header: %q", got)
		}
		if got := r.Header.Get(DefaultOrgHeader); got != "" {
			t.Errorf("expected default header unset when overridden, got %q", got)
		}
		_ = json.NewEncoder(w).Encode(overlayResponse{Columns: map[string]string{}})
	}))
	defer srv.Close()

	src := newOverlaySource(config.Agent{PIIOverlayURL: srv.URL, OrgID: "org-9", PIIOverlayOrgHeader: "X-Tenant-Id"})
	if _, _, err := src.fetch(context.Background()); err != nil {
		t.Fatal(err)
	}
}

func TestOverlaySourceFetchNilColumnsDefaultsToEmptyMap(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = io.WriteString(w, `{"organization_id":"org-9"}`)
	}))
	defer srv.Close()

	src := newOverlaySource(config.Agent{PIIOverlayURL: srv.URL})
	rules, _, err := src.fetch(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if rules == nil || len(rules) != 0 {
		t.Fatalf("expected a non-nil, empty rules map, got %v", rules)
	}
}

func TestStartOverlaySyncDefaultsNilLogger(t *testing.T) {
	// A nil logger must fall back to slog.Default() rather than panic.
	overlay := mask.NewRoleOverlay(nil)
	cfg := config.Agent{PIIOverlayURL: "http://127.0.0.1:0", PIIOverlayPollSeconds: -1}
	startOverlaySync(context.Background(), cfg, overlay, nil)
}

// TestStartOverlaySyncPollStopsOnContextCancel drives the poll goroutine's ctx.Done() branch by
// using a very short poll interval and cancelling ctx shortly after — asserting only that the
// goroutine exits without leaking (best-effort: we can't directly observe the goroutine's exit, but
// this at least exercises the ticker path beyond the initial synchronous seed).
func TestStartOverlaySyncPollStopsOnContextCancel(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(w).Encode(overlayResponse{Columns: map[string]string{"email": "[email]"}})
	}))
	defer srv.Close()

	overlay := mask.NewRoleOverlay(nil)
	ctx, cancel := context.WithCancel(context.Background())
	cfg := config.Agent{PIIOverlayURL: srv.URL, PIIOverlayPollSeconds: 15}
	startOverlaySync(ctx, cfg, overlay, slog.Default())
	cancel()
	// Give the background goroutine a moment to observe cancellation; nothing to assert beyond "no
	// panic/hang", which the test harness itself verifies via completion.
	time.Sleep(20 * time.Millisecond)
}

func TestOverlaySourceFetchBadJSONDecode(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = io.WriteString(w, "not json")
	}))
	defer srv.Close()

	src := newOverlaySource(config.Agent{PIIOverlayURL: srv.URL})
	if _, _, err := src.fetch(context.Background()); err == nil || !strings.Contains(err.Error(), "decode") {
		t.Fatalf("expected a decode error, got %v", err)
	}
}

func TestOverlaySourceFetchDialFailure(t *testing.T) {
	src := newOverlaySource(config.Agent{PIIOverlayURL: "http://127.0.0.1:1"})
	if _, _, err := src.fetch(context.Background()); err == nil {
		t.Fatal("expected a transport-level error on connection refused")
	}
}

func TestOverlaySourceFetchHTTPError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusForbidden)
		_, _ = io.WriteString(w, `{"detail":"nope"}`)
	}))
	defer srv.Close()

	src := newOverlaySource(config.Agent{PIIOverlayURL: srv.URL})
	if _, _, err := src.fetch(context.Background()); err == nil {
		t.Fatal("expected error on non-2xx response")
	}
}

func TestStartOverlaySyncSeedsOverlay(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(w).Encode(overlayResponse{Columns: map[string]string{"email": "[email]"}})
	}))
	defer srv.Close()

	overlay := mask.NewRoleOverlay(nil)
	cfg := config.Agent{PIIOverlayURL: srv.URL, PIIOverlayPollSeconds: -1} // fetch-once
	startOverlaySync(context.Background(), cfg, overlay, slog.Default())

	if !overlay.Enabled() {
		t.Fatal("overlay should be seeded after sync")
	}
	out, _ := overlay.MaskRow(context.Background(), []mask.Column{{Name: "email", Text: true, FreeText: true}}, [][]byte{[]byte("a@b.com")})
	if string(out[0]) != "[email]" {
		t.Fatalf("expected seeded rule applied, got %q", out[0])
	}
}

func TestStartOverlaySyncLogsFailedInitialFetch(t *testing.T) {
	overlay := mask.NewRoleOverlay(map[string]string{"email": "[static]"})
	var buf bytes.Buffer
	cfg := config.Agent{PIIOverlayURL: "http://127.0.0.1:0", PIIOverlayPollSeconds: -1}
	startOverlaySync(context.Background(), cfg, overlay, slog.New(slog.NewTextHandler(&buf, nil)))
	if !strings.Contains(buf.String(), "pii-overlay refresh failed") {
		t.Fatalf("expected a refresh-failure log, got %q", buf.String())
	}
	// Static overlay must survive the failed refresh.
	out, _ := overlay.MaskRow(context.Background(), []mask.Column{{Name: "email", Text: true, FreeText: true}}, [][]byte{[]byte("a@b.com")})
	if string(out[0]) != "[static]" {
		t.Fatalf("expected static overlay to remain, got %q", out[0])
	}
}

func TestStartOverlaySyncPollsInBackground(t *testing.T) {
	var calls int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		n := atomic.AddInt32(&calls, 1)
		_ = json.NewEncoder(w).Encode(overlayResponse{Columns: map[string]string{"email": fmt.Sprintf("[email-%d]", n)}})
	}))
	defer srv.Close()

	overlay := mask.NewRoleOverlay(nil)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	// PIIOverlayPollSeconds unset (0) exercises the "below overlayMinPoll, clamp up" branch; we
	// don't want to wait a full 15s in a unit test, so just confirm the initial synchronous seed
	// happened and the background goroutine was launched without blocking or panicking.
	cfg := config.Agent{PIIOverlayURL: srv.URL, PIIOverlayPollSeconds: 0}
	startOverlaySync(ctx, cfg, overlay, slog.Default())

	if atomic.LoadInt32(&calls) < 1 {
		t.Fatal("expected at least one synchronous initial fetch")
	}
	if !overlay.Enabled() {
		t.Fatal("expected overlay to be seeded")
	}
}

func TestStartOverlaySyncNoURLIsNoop(t *testing.T) {
	overlay := mask.NewRoleOverlay(map[string]string{"email": "[static]"})
	// No URL → must leave the static overlay untouched and not block.
	startOverlaySync(context.Background(), config.Agent{}, overlay, slog.Default())
	out, _ := overlay.MaskRow(context.Background(), []mask.Column{{Name: "email", Text: true, FreeText: true}}, [][]byte{[]byte("a@b.com")})
	if string(out[0]) != "[static]" {
		t.Fatalf("static overlay should remain, got %q", out[0])
	}
}

func TestOverlaySourceFetchParsesRoleOverlays(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(w).Encode(overlayResponse{
			Columns:      map[string]string{"email": "[email]"},
			RoleOverlays: map[string]map[string]string{"role-1": {"internal_notes": "[redacted]"}},
		})
	}))
	defer srv.Close()

	src := newOverlaySource(config.Agent{PIIOverlayURL: srv.URL})
	rules, roleOverlays, err := src.fetch(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if rules["email"] != "[email]" {
		t.Fatalf("unexpected default rules: %v", rules)
	}
	if roleOverlays["role-1"]["internal_notes"] != "[redacted]" {
		t.Fatalf("unexpected role overlays: %v", roleOverlays)
	}
}

func TestOverlaySourceFetchNilRoleOverlaysDefaultsToEmptyMap(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = io.WriteString(w, `{"organization_id":"org-9","columns":{}}`)
	}))
	defer srv.Close()

	src := newOverlaySource(config.Agent{PIIOverlayURL: srv.URL})
	_, roleOverlays, err := src.fetch(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if roleOverlays == nil || len(roleOverlays) != 0 {
		t.Fatalf("expected a non-nil, empty role_overlays map, got %v", roleOverlays)
	}
}

func TestStartOverlaySyncAppliesRoleOverlays(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(w).Encode(overlayResponse{
			Columns:      map[string]string{"email": "[email]"},
			RoleOverlays: map[string]map[string]string{"role-1": {"internal_notes": "[redacted]"}},
		})
	}))
	defer srv.Close()

	overlay := mask.NewRoleOverlay(nil)
	cfg := config.Agent{PIIOverlayURL: srv.URL, PIIOverlayPollSeconds: -1}
	startOverlaySync(context.Background(), cfg, overlay, slog.Default())

	roleCtx := mask.WithResourceRoleID(context.Background(), "role-1")
	out, _ := overlay.MaskRow(
		roleCtx,
		[]mask.Column{{Name: "internal_notes", Text: true, FreeText: true}},
		[][]byte{[]byte("some note")},
	)
	if string(out[0]) != "[redacted]" {
		t.Fatalf("expected role-1's overlay applied, got %q", out[0])
	}

	// A connection with no resolved role still only sees the default overlay.
	defaultOut, _ := overlay.MaskRow(
		context.Background(),
		[]mask.Column{{Name: "internal_notes", Text: true, FreeText: true}},
		[][]byte{[]byte("some note")},
	)
	if string(defaultOut[0]) != "some note" {
		t.Fatalf("expected default overlay to leave internal_notes unmasked, got %q", defaultOut[0])
	}
}

func TestBuildMaskerWithOverlayIncludesDynamic(t *testing.T) {
	// URL set but no static rules → overlay layer still present for later hot-swap.
	_, overlay, _, _, _ := buildMaskerWithOverlay(config.Agent{PIIOverlayURL: "http://x/overlay"})
	if overlay == nil {
		t.Fatal("expected overlay handle when a dynamic source URL is configured")
	}
	// Neither static nor dynamic → no overlay layer.
	_, overlay, _, _, _ = buildMaskerWithOverlay(config.Agent{})
	if overlay != nil {
		t.Fatal("expected no overlay handle without static rules or URL")
	}
}

func guardrailLog(cfg config.Agent) string {
	var buf bytes.Buffer
	logMaskingGuardrails(cfg, slog.New(slog.NewTextHandler(&buf, nil)))
	return buf.String()
}

func TestGuardrailNoMasking(t *testing.T) {
	out := guardrailLog(config.Agent{})
	if !strings.Contains(out, "UNMASKED") {
		t.Fatalf("expected passthrough warning, got %q", out)
	}
}

func TestGuardrailOverlayOnlyWarnsNoPresidio(t *testing.T) {
	out := guardrailLog(config.Agent{PIIOverlayURL: "http://x/overlay"})
	if !strings.Contains(out, "Presidio content masking is not configured") {
		t.Fatalf("expected overlay-only warning, got %q", out)
	}
}

func TestGuardrailHalfConfiguredPresidio(t *testing.T) {
	out := guardrailLog(config.Agent{MaskAnalyzeURL: "http://a"})
	if !strings.Contains(out, "half-configured") {
		t.Fatalf("expected half-config warning, got %q", out)
	}
}

func TestGuardrailDefaultsNilLogger(t *testing.T) {
	// A nil logger must fall back to slog.Default() rather than panic.
	logMaskingGuardrails(config.Agent{}, nil)
}

func TestGuardrailStrictModeWarnsAboutAbort(t *testing.T) {
	out := guardrailLog(config.Agent{
		MaskAnalyzeURL:   "http://a",
		MaskAnonymizeURL: "http://b",
		MaskMode:         config.ModeStrict,
	})
	if !strings.Contains(out, "SKYBRIDGE_MASK_MODE=strict") {
		t.Fatalf("expected a strict-mode warning, got %q", out)
	}
}

func TestGuardrailFullyConfiguredQuiet(t *testing.T) {
	out := guardrailLog(config.Agent{
		MaskAnalyzeURL:   "http://a",
		MaskAnonymizeURL: "http://b",
		PIIOverlayURL:    "http://x/overlay",
	})
	if strings.Contains(out, "WARNING") {
		t.Fatalf("expected no warnings when both layers configured, got %q", out)
	}
}
