package metrics

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"context"
)

func TestRecorder_DisabledWhenURLUnset(t *testing.T) {
	r := New(Config{}, nil)
	if r.Enabled() {
		t.Fatal("expected Enabled() false when URL is unset")
	}
	// Must be safe no-ops: no panics, no pending growth.
	r.RecordAnalyzed("postgres__primary", "recognizer")
	r.RecordMasked("postgres__primary", "EMAIL_ADDRESS", 10, "recognizer")
	if n := len(r.drain()); n != 0 {
		t.Fatalf("expected no pending buckets when disabled, got %d", n)
	}
}

func TestRecorder_AccumulatesPerConnectionEntityTypeSource(t *testing.T) {
	r := New(Config{URL: "http://unused"}, nil)
	r.RecordAnalyzed("postgres__primary", "recognizer")
	r.RecordAnalyzed("postgres__primary", "recognizer")
	r.RecordMasked("postgres__primary", "EMAIL_ADDRESS", 5, "recognizer")
	r.RecordMasked("postgres__primary", "EMAIL_ADDRESS", 7, "recognizer")
	r.RecordMasked("postgres__primary", "email_fields", 3, "field_rule")

	pending := r.drain()

	analyzedKey := bucketKey{connectionKey: "postgres__primary", entityType: unspecifiedEntityType, source: "recognizer"}
	maskedKey := bucketKey{connectionKey: "postgres__primary", entityType: "EMAIL_ADDRESS", source: "recognizer"}
	fieldRuleKey := bucketKey{connectionKey: "postgres__primary", entityType: "email_fields", source: "field_rule"}

	if got := pending[analyzedKey]; got == nil || got.countAnalyzed != 2 {
		t.Fatalf("expected 2 analyzed, got %+v", got)
	}
	if got := pending[maskedKey]; got == nil || got.countMasked != 2 || got.bytesMasked != 12 {
		t.Fatalf("expected 2 masked / 12 bytes, got %+v", got)
	}
	if got := pending[fieldRuleKey]; got == nil || got.countMasked != 1 || got.bytesMasked != 3 {
		t.Fatalf("expected field_rule bucket distinct from recognizer bucket, got %+v", got)
	}
	// recognizer and field_rule entity-type vocabularies must never be merged into one bucket.
	if len(pending) != 3 {
		t.Fatalf("expected 3 distinct buckets, got %d: %+v", len(pending), pending)
	}
}

func TestRecorder_FlushSendsBatchAndClearsPending(t *testing.T) {
	var mu sync.Mutex
	var got batchBody
	var calls int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&calls, 1)
		mu.Lock()
		_ = json.NewDecoder(r.Body).Decode(&got)
		mu.Unlock()
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	r := New(Config{URL: srv.URL, PushInterval: time.Hour}, nil)
	r.RecordMasked("postgres__primary", "EMAIL_ADDRESS", 10, "recognizer")
	r.flush(context.Background())

	if atomic.LoadInt32(&calls) != 1 {
		t.Fatalf("expected exactly one flush POST, got %d", calls)
	}
	mu.Lock()
	defer mu.Unlock()
	if len(got.Entries) != 1 || got.Entries[0].ConnectionKey != "postgres__primary" {
		t.Fatalf("unexpected batch body: %+v", got)
	}
	if pending := r.drain(); len(pending) != 0 {
		t.Fatal("expected pending cleared after a successful flush")
	}
}

func TestRecorder_FailedFlushRetainsBatchForRetry(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer srv.Close()

	r := New(Config{URL: srv.URL, PushInterval: time.Hour}, nil)
	r.RecordMasked("postgres__primary", "EMAIL_ADDRESS", 10, "recognizer")
	r.flush(context.Background())

	pending := r.drain()
	if len(pending) != 1 {
		t.Fatalf("expected the failed batch retained for retry, got %d buckets", len(pending))
	}
}

func TestRecorder_OverflowFoldsIntoOtherBucketWithoutPanic(t *testing.T) {
	r := New(Config{URL: "http://unused"}, nil)
	for i := 0; i < maxPendingBuckets+50; i++ {
		r.RecordMasked("conn", "ENTITY_"+itoa(i), 1, "recognizer")
	}
	pending := r.drain()
	if len(pending) > maxPendingBuckets {
		t.Fatalf("expected pending capped at %d, got %d", maxPendingBuckets, len(pending))
	}
	otherKey := bucketKey{connectionKey: "conn", entityType: otherEntityType, source: "recognizer"}
	other, ok := pending[otherKey]
	if !ok || other.countMasked == 0 {
		t.Fatalf("expected overflow observations folded into OTHER bucket, got %+v", pending[otherKey])
	}
}

func TestRecorder_StartFlushesOnShutdown(t *testing.T) {
	var calls int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&calls, 1)
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	r := New(Config{URL: srv.URL, PushInterval: time.Hour}, nil)
	ctx, cancel := context.WithCancel(context.Background())
	r.RecordMasked("postgres__primary", "EMAIL_ADDRESS", 10, "recognizer")
	r.Start(ctx)
	cancel()
	// Allow the goroutine's ctx.Done() branch to run its flush.
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if atomic.LoadInt32(&calls) > 0 {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	if atomic.LoadInt32(&calls) == 0 {
		t.Fatal("expected Start's shutdown path to flush pending buckets")
	}
}

func TestConnectionKey_LowercasesDriverOnly(t *testing.T) {
	if got := ConnectionKey("Postgres", "Prod-Readonly"); got != "postgres__Prod-Readonly" {
		t.Fatalf("unexpected connection key: %q", got)
	}
}
