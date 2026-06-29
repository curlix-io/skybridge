package agent

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"log"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/curlix-io/skybridge/internal/config"
	"github.com/curlix-io/skybridge/internal/mask"
)

func TestOverlaySourceFetchParses(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if got := r.Header.Get("Authorization"); got != "Bearer tok-1" {
			t.Errorf("missing/!bearer auth header: %q", got)
		}
		if got := r.Header.Get("X-Curlix-Organization-Id"); got != "org-9" {
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
	rules, err := src.fetch(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if rules["email"] != "[email]" || rules["ssn"] != "[ssn]" {
		t.Fatalf("unexpected rules: %v", rules)
	}
}

func TestOverlaySourceFetchHTTPError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusForbidden)
		_, _ = io.WriteString(w, `{"detail":"nope"}`)
	}))
	defer srv.Close()

	src := newOverlaySource(config.Agent{PIIOverlayURL: srv.URL})
	if _, err := src.fetch(context.Background()); err == nil {
		t.Fatal("expected error on non-2xx response")
	}
}

func TestStartOverlaySyncSeedsOverlay(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(w).Encode(overlayResponse{Columns: map[string]string{"email": "[email]"}})
	}))
	defer srv.Close()

	overlay := mask.NewOverlay(nil)
	cfg := config.Agent{PIIOverlayURL: srv.URL, PIIOverlayPollSeconds: -1} // fetch-once
	startOverlaySync(context.Background(), cfg, overlay, log.Default())

	if !overlay.Enabled() {
		t.Fatal("overlay should be seeded after sync")
	}
	out, _ := overlay.MaskRow(context.Background(), []mask.Column{{Name: "email", Text: true}}, [][]byte{[]byte("a@b.com")})
	if string(out[0]) != "[email]" {
		t.Fatalf("expected seeded rule applied, got %q", out[0])
	}
}

func TestStartOverlaySyncNoURLIsNoop(t *testing.T) {
	overlay := mask.NewOverlay(map[string]string{"email": "[static]"})
	// No URL → must leave the static overlay untouched and not block.
	startOverlaySync(context.Background(), config.Agent{}, overlay, log.Default())
	out, _ := overlay.MaskRow(context.Background(), []mask.Column{{Name: "email", Text: true}}, [][]byte{[]byte("a@b.com")})
	if string(out[0]) != "[static]" {
		t.Fatalf("static overlay should remain, got %q", out[0])
	}
}

func TestBuildMaskerWithOverlayIncludesDynamic(t *testing.T) {
	// URL set but no static rules → overlay layer still present for later hot-swap.
	_, overlay := buildMaskerWithOverlay(config.Agent{PIIOverlayURL: "http://x/overlay"})
	if overlay == nil {
		t.Fatal("expected overlay handle when a dynamic source URL is configured")
	}
	// Neither static nor dynamic → no overlay layer.
	_, overlay = buildMaskerWithOverlay(config.Agent{})
	if overlay != nil {
		t.Fatal("expected no overlay handle without static rules or URL")
	}
}

func guardrailLog(cfg config.Agent) string {
	var buf bytes.Buffer
	logMaskingGuardrails(cfg, log.New(&buf, "", 0))
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
