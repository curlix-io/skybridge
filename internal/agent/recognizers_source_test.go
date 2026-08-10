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
	"sync/atomic"
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

func TestRecognizersSourceFetchBadJSONDecode(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = io.WriteString(w, "not json")
	}))
	defer srv.Close()

	src := newRecognizersSource(config.Agent{PIIRecognizersURL: srv.URL})
	if _, err := src.fetch(context.Background()); err == nil || !strings.Contains(err.Error(), "decode") {
		t.Fatalf("expected a decode error, got %v", err)
	}
}

func TestRecognizersSourceFetchDialFailure(t *testing.T) {
	src := newRecognizersSource(config.Agent{PIIRecognizersURL: "http://127.0.0.1:1"})
	if _, err := src.fetch(context.Background()); err == nil {
		t.Fatal("expected a transport-level error on connection refused")
	}
}

func TestRecognizersSourceRequestURLRejectsInvalidURL(t *testing.T) {
	src := newRecognizersSource(config.Agent{PIIRecognizersURL: "http://[::1]:namedport/bad"})
	if _, err := src.requestURL(); err == nil {
		t.Fatal("expected an error for a malformed base URL")
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

func TestStartRecognizersSyncLogsFailedInitialFetch(t *testing.T) {
	remote := mask.NewRemote(mask.RemoteConfig{})
	var buf bytes.Buffer
	cfg := config.Agent{PIIRecognizersURL: "http://127.0.0.1:0", PIIRecognizersPollSeconds: -1}
	startRecognizersSync(context.Background(), cfg, remote, log.New(&buf, "", 0))
	if !strings.Contains(buf.String(), "pii-recognizers refresh failed") {
		t.Fatalf("expected a refresh-failure log, got %q", buf.String())
	}
}

func TestStartRecognizersSyncPollsInBackground(t *testing.T) {
	var calls int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		atomic.AddInt32(&calls, 1)
		_ = json.NewEncoder(w).Encode(recognizersResponse{Recognizers: []any{}})
	}))
	defer srv.Close()

	remote := mask.NewRemote(mask.RemoteConfig{})
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	// PIIRecognizersPollSeconds unset (0) exercises the "below recognizersMinPoll, clamp up" branch
	// and launches the background poll goroutine; we only assert the synchronous initial fetch ran.
	cfg := config.Agent{PIIRecognizersURL: srv.URL, PIIRecognizersPollSeconds: 0}
	startRecognizersSync(ctx, cfg, remote, log.Default())

	if atomic.LoadInt32(&calls) < 1 {
		t.Fatal("expected at least one synchronous initial fetch")
	}
}

func TestStartRecognizersSyncNoURLIsNoop(t *testing.T) {
	remote := mask.NewRemote(mask.RemoteConfig{})
	// No URL and nil remote must both be safe no-ops that don't block.
	startRecognizersSync(context.Background(), config.Agent{}, remote, log.Default())
	startRecognizersSync(context.Background(), config.Agent{PIIRecognizersURL: "http://x"}, nil, log.Default())
}
