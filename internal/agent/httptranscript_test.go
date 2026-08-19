package agent

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/curlix-io/skybridge/internal/config"
	"github.com/curlix-io/skybridge/internal/wire"
)

func TestNewHTTPTranscriptRecorderNoopWhenDisabled(t *testing.T) {
	r := newHTTPTranscriptRecorder(config.Agent{SessionTranscriptReportURL: "http://example.invalid"}, "postgres")
	if _, ok := r.(wire.NoopRecorder); !ok {
		t.Fatalf("expected wire.NoopRecorder when replay is disabled, got %T", r)
	}
}

func TestNewHTTPTranscriptRecorderNoopWhenNoURL(t *testing.T) {
	r := newHTTPTranscriptRecorder(config.Agent{SessionReplayEnabled: true}, "postgres")
	if _, ok := r.(wire.NoopRecorder); !ok {
		t.Fatalf("expected wire.NoopRecorder when report URL is unset, got %T", r)
	}
}

func TestNewHTTPTranscriptRecorderLiveWhenEnabled(t *testing.T) {
	r := newHTTPTranscriptRecorder(config.Agent{SessionReplayEnabled: true, SessionTranscriptReportURL: "http://example.invalid"}, "kubernetes")
	tr, ok := r.(*httpTranscriptRecorder)
	if !ok {
		t.Fatalf("expected *httpTranscriptRecorder, got %T", r)
	}
	if tr.sessionID == "" || tr.driver != "kubernetes" || tr.maxBytes != 5<<20 {
		t.Fatalf("unexpected recorder: %+v", tr)
	}
}

func TestHTTPTranscriptRecorderRecordInputAndOutput(t *testing.T) {
	r := newHTTPTranscriptRecorder(config.Agent{SessionReplayEnabled: true, SessionTranscriptReportURL: "http://example.invalid"}, "postgres").(*httpTranscriptRecorder)
	r.RecordInput([]byte("hello"))
	r.RecordOutput("world")
	r.RecordInput(nil)
	r.RecordOutput("")

	if len(r.chunks) != 2 {
		t.Fatalf("expected 2 chunks, got %d: %+v", len(r.chunks), r.chunks)
	}
	if r.chunks[0].Direction != "input" || r.chunks[0].Text != "hello" {
		t.Fatalf("unexpected first chunk: %+v", r.chunks[0])
	}
	if r.chunks[1].Direction != "output" || r.chunks[1].Text != "world" {
		t.Fatalf("unexpected second chunk: %+v", r.chunks[1])
	}
}

func TestHTTPTranscriptRecorderTruncatesAtMaxBytes(t *testing.T) {
	r := newHTTPTranscriptRecorder(config.Agent{SessionReplayEnabled: true, SessionTranscriptReportURL: "http://example.invalid", SessionReplayMaxBytes: 5}, "postgres").(*httpTranscriptRecorder)
	r.RecordInput([]byte("hello"))
	r.RecordOutput("world")
	if len(r.chunks) != 1 || !r.truncated {
		t.Fatalf("expected truncation after first chunk, got chunks=%d truncated=%v", len(r.chunks), r.truncated)
	}
}

func TestFlushHTTPTranscriptPostsChunksWithBearer(t *testing.T) {
	var gotAuth string
	var gotBody httpTranscriptReport
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		gotAuth = req.Header.Get("Authorization")
		_ = json.NewDecoder(req.Body).Decode(&gotBody)
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	r := newHTTPTranscriptRecorder(config.Agent{
		SessionReplayEnabled:       true,
		SessionTranscriptReportURL: srv.URL,
		OrgID:                      "org-1",
		CredentialExchangeToken:    "tok-abc",
	}, "kubernetes").(*httpTranscriptRecorder)
	r.RecordInput([]byte("GET /pods"))
	r.RecordOutput(`{"kind":"PodList"}`)

	flushHTTPTranscript(context.Background(), r, nil)

	if gotAuth != "Bearer tok-abc" {
		t.Fatalf("expected bearer token, got %q", gotAuth)
	}
	if gotBody.OrganizationID != "org-1" || gotBody.Driver != "kubernetes" || len(gotBody.TranscriptChunks) != 2 {
		t.Fatalf("unexpected report body: %+v", gotBody)
	}
}

func TestFlushHTTPTranscriptNoopOnEmptyOrWrongType(t *testing.T) {
	// No panic/hang on wire.NoopRecorder{} (nothing to flush).
	flushHTTPTranscript(context.Background(), wire.NoopRecorder{}, nil)

	// No panic/hang when there are no chunks yet, even with a live recorder.
	r := newHTTPTranscriptRecorder(config.Agent{SessionReplayEnabled: true, SessionTranscriptReportURL: "http://example.invalid"}, "postgres")
	done := make(chan struct{})
	go func() {
		flushHTTPTranscript(context.Background(), r, nil)
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("flushHTTPTranscript did not return promptly for an empty recorder")
	}
}

func TestNewLocalSessionIDIsUnique(t *testing.T) {
	a := newLocalSessionID()
	b := newLocalSessionID()
	if a == "" || b == "" || a == b {
		t.Fatalf("expected two distinct non-empty session ids, got %q and %q", a, b)
	}
}
