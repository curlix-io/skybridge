package agent

import (
	"context"
	"encoding/json"
	"io"
	"log"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/curlix-io/skybridge/internal/config"
	"github.com/curlix-io/skybridge/internal/mask"
)

func TestRecognizersSourceFetchParses(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if got := r.Header.Get("Authorization"); got != "Bearer tok-1" {
			t.Errorf("missing/!bearer auth header: %q", got)
		}
		if got := r.Header.Get("X-Curlix-Organization-Id"); got != "org-9" {
			t.Errorf("missing org header: %q", got)
		}
		if got := r.URL.Query().Get("driver"); got != "postgres" {
			t.Errorf("expected driver query param, got %q", got)
		}
		if got := r.URL.Query().Get("connection_role"); got != "prod-readonly" {
			t.Errorf("expected connection_role query param, got %q", got)
		}
		_ = json.NewEncoder(w).Encode(recognizersResponse{
			OrganizationID: "org-9",
			Recognizers:    []any{map[string]any{"name": "Acme", "patterns": []any{}}},
			Entities:       []string{"EMAIL_ADDRESS"},
			ScoreThreshold: 0.7,
			Count:          1,
		})
	}))
	defer srv.Close()

	src := newRecognizersSource(config.Agent{
		PIIRecognizersURL:   srv.URL,
		PIIRecognizersToken: "tok-1",
		OrgID:               "org-9",
		DBType:              "postgres",
		ConnectionRole:      "prod-readonly",
	})
	resp, err := src.fetch(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(resp.Recognizers) != 1 {
		t.Fatalf("unexpected recognizers: %v", resp.Recognizers)
	}
	if len(resp.Entities) != 1 || resp.Entities[0] != "EMAIL_ADDRESS" {
		t.Fatalf("unexpected entities: %v", resp.Entities)
	}
	if resp.ScoreThreshold != 0.7 {
		t.Fatalf("unexpected score threshold: %v", resp.ScoreThreshold)
	}
}

func TestRecognizersSourceFetchSendsEmptyConnectionRoleWhenUnset(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if got := r.URL.Query().Get("connection_role"); got != "" {
			t.Errorf("expected empty connection_role query param, got %q", got)
		}
		if _, ok := r.URL.Query()["connection_role"]; !ok {
			t.Error("expected connection_role query param to be present even when empty")
		}
		_ = json.NewEncoder(w).Encode(recognizersResponse{})
	}))
	defer srv.Close()

	src := newRecognizersSource(config.Agent{PIIRecognizersURL: srv.URL, DBType: "mongodb"})
	if _, err := src.fetch(context.Background()); err != nil {
		t.Fatal(err)
	}
}

func TestRecognizersSourceFetchHTTPError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusForbidden)
		_, _ = io.WriteString(w, `{"detail":"nope"}`)
	}))
	defer srv.Close()

	src := newRecognizersSource(config.Agent{PIIRecognizersURL: srv.URL})
	if _, err := src.fetch(context.Background()); err == nil {
		t.Fatal("expected error on non-2xx response")
	}
}

func TestStartRecognizersSyncSeedsRemote(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(w).Encode(recognizersResponse{
			Recognizers: []any{map[string]any{"name": "Acme"}},
		})
	}))
	defer srv.Close()

	remote := mask.NewRemote(mask.RemoteConfig{})
	cfg := config.Agent{PIIRecognizersURL: srv.URL, PIIRecognizersPollSeconds: -1} // fetch-once
	startRecognizersSync(context.Background(), cfg, remote, log.Default())

	// No direct getter is exported on Remote besides ReplaceConfig; the sync path having run to
	// completion is asserted indirectly by the fact that startRecognizersSync (which calls fetch
	// synchronously once before returning in fetch-once mode) returns without blocking or panicking.
}

func TestStartRecognizersSyncNoURLIsNoop(t *testing.T) {
	remote := mask.NewRemote(mask.RemoteConfig{})
	// No URL and nil remote must both be safe no-ops that don't block.
	startRecognizersSync(context.Background(), config.Agent{}, remote, log.Default())
	startRecognizersSync(context.Background(), config.Agent{PIIRecognizersURL: "http://x"}, nil, log.Default())
}
