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

func TestRecorder_RecordMaskedDefaultsEmptyEntityTypeAndClampsNegativeBytes(t *testing.T) {
	r := New(Config{URL: "http://unused"}, nil)
	r.RecordMasked("conn", "  ", -5, "recognizer")
	pending := r.drain()
	key := bucketKey{connectionKey: "conn", entityType: unspecifiedEntityType, source: "recognizer"}
	got, ok := pending[key]
	if !ok {
		t.Fatalf("expected empty entityType to fall back to unspecifiedEntityType, got %+v", pending)
	}
	if got.countMasked != 1 || got.bytesMasked != 0 {
		t.Fatalf("expected negative byteCount clamped to 0, got %+v", got)
	}
}

func TestRecorder_StartNoopWhenDisabled(t *testing.T) {
	r := New(Config{}, nil) // no URL: disabled
	ctx, cancel := context.WithCancel(context.Background())
	r.Start(ctx) // must not start a goroutine or panic
	cancel()
	// No assertion beyond "doesn't panic/hang" — Enabled()==false makes Start a no-op by contract.
}

func TestRecorder_StartFlushesPeriodically(t *testing.T) {
	var calls int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&calls, 1)
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	r := New(Config{URL: srv.URL, PushInterval: minPushSeconds * time.Second}, nil)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	r.RecordMasked("postgres__primary", "EMAIL_ADDRESS", 10, "recognizer")
	r.Start(ctx)

	deadline := time.Now().Add(8 * time.Second)
	for time.Now().Before(deadline) {
		if atomic.LoadInt32(&calls) > 0 {
			break
		}
		time.Sleep(50 * time.Millisecond)
	}
	if atomic.LoadInt32(&calls) == 0 {
		t.Fatal("expected the ticker to trigger at least one periodic flush")
	}
}

func TestRecorder_FlushNoopWhenNothingPending(t *testing.T) {
	var calls int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&calls, 1)
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	r := New(Config{URL: srv.URL, PushInterval: time.Hour}, nil)
	r.flush(context.Background()) // nothing recorded yet
	if atomic.LoadInt32(&calls) != 0 {
		t.Fatal("expected flush to skip the POST entirely when pending is empty")
	}
}

func TestRecorder_PushSendsTokenAndOrgIDHeaders(t *testing.T) {
	var gotAuth, gotOrg string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotAuth = r.Header.Get("Authorization")
		gotOrg = r.Header.Get("X-Curlix-Organization-Id")
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	r := New(Config{URL: srv.URL, Token: "secret-token", OrgID: "org-42", PushInterval: time.Hour}, nil)
	r.RecordMasked("postgres__primary", "EMAIL_ADDRESS", 10, "recognizer")
	r.flush(context.Background())

	if gotAuth != "Bearer secret-token" {
		t.Fatalf("expected bearer token header, got %q", gotAuth)
	}
	if gotOrg != "org-42" {
		t.Fatalf("expected org id header, got %q", gotOrg)
	}
}

func TestRecorder_PushOmitsHeadersWhenUnset(t *testing.T) {
	var sawAuth, sawOrg bool
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		sawAuth = r.Header.Get("Authorization") != ""
		sawOrg = r.Header.Get("X-Curlix-Organization-Id") != ""
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	r := New(Config{URL: srv.URL, PushInterval: time.Hour}, nil)
	r.RecordMasked("postgres__primary", "EMAIL_ADDRESS", 10, "recognizer")
	r.flush(context.Background())

	if sawAuth || sawOrg {
		t.Fatalf("expected no auth/org headers when Token/OrgID are unset, auth=%v org=%v", sawAuth, sawOrg)
	}
}

func TestRecorder_PushFailsOnTransportError(t *testing.T) {
	// Port 0 on loopback is never listening, forcing a transport-level error from http.Client.Do,
	// distinct from the non-2xx-status branch exercised by TestRecorder_FailedFlushRetainsBatchForRetry.
	r := New(Config{URL: "http://127.0.0.1:0", PushInterval: time.Hour}, nil)
	r.RecordMasked("conn", "EMAIL_ADDRESS", 10, "recognizer")
	r.flush(context.Background())
	if pending := r.drain(); len(pending) != 1 {
		t.Fatalf("expected the batch retained after a transport error, got %d buckets", len(pending))
	}
}

func TestRecorder_RestoreMergesIntoExistingBucket(t *testing.T) {
	r := New(Config{URL: "http://unused"}, nil)
	r.RecordMasked("conn", "EMAIL_ADDRESS", 5, "recognizer")
	// Simulate a flush cycle: drain, then a second observation arrives before restore runs.
	drained := r.drain()
	r.RecordMasked("conn", "EMAIL_ADDRESS", 7, "recognizer")
	r.restore(drained)

	key := bucketKey{connectionKey: "conn", entityType: "EMAIL_ADDRESS", source: "recognizer"}
	pending := r.drain()
	got, ok := pending[key]
	if !ok || got.countMasked != 2 || got.bytesMasked != 12 {
		t.Fatalf("expected restore to merge counts into the existing bucket, got %+v", got)
	}
}

func TestRecorder_RestoreFoldsOverflowIntoOtherBucket(t *testing.T) {
	r := New(Config{URL: "http://unused"}, nil)
	// Fill pending to the cap with distinct buckets.
	for i := 0; i < maxPendingBuckets; i++ {
		r.RecordMasked("conn", "ENTITY_"+itoa(i), 1, "recognizer")
	}
	drained := r.drain()
	// Now restore a brand-new, never-seen bucket while pending is (about to be) full again.
	for i := 0; i < maxPendingBuckets; i++ {
		r.RecordMasked("conn", "ENTITY_"+itoa(i), 1, "recognizer")
	}
	r.restore(map[bucketKey]*bucketCounts{
		{connectionKey: "conn", entityType: "BRAND_NEW", source: "recognizer"}: {countMasked: 3},
	})
	_ = drained

	pending := r.drain()
	if len(pending) > maxPendingBuckets {
		t.Fatalf("expected pending capped at %d after restore, got %d", maxPendingBuckets, len(pending))
	}
	otherKey := bucketKey{connectionKey: "conn", entityType: otherEntityType, source: "recognizer"}
	if _, ok := pending[otherKey]; !ok {
		t.Fatalf("expected overflow from restore folded into OTHER bucket, got %+v", pending)
	}
}

func TestItoaNegativeNumbers(t *testing.T) {
	if got := itoa(-42); got != "-42" {
		t.Fatalf("expected -42, got %q", got)
	}
	if got := itoa(0); got != "0" {
		t.Fatalf("expected 0, got %q", got)
	}
	if got := itoa(7); got != "7" {
		t.Fatalf("expected 7, got %q", got)
	}
}

func TestHTTPStatusErrorMessage(t *testing.T) {
	err := &httpStatusError{url: "http://x", status: 503, body: "unavailable"}
	want := "masking-metrics http://x -> 503: unavailable"
	if got := err.Error(); got != want {
		t.Fatalf("expected %q, got %q", want, got)
	}
}

func TestConnectionKey_LowercasesDriverOnly(t *testing.T) {
	if got := ConnectionKey("Postgres", "Prod-Readonly"); got != "postgres__Prod-Readonly" {
		t.Fatalf("unexpected connection key: %q", got)
	}
}
