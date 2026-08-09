package remotestore

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/curlix-io/skybridge/internal/config"
	"github.com/curlix-io/skybridge/internal/pathlabel/label"
)

func testConfig(url string) config.Agent {
	return config.Agent{
		PathLabelURL:         url,
		OrgID:                "org1",
		PathLabelPollSeconds: 15,
		PathLabelPushSeconds: 5,
	}
}

func TestStore_PullPopulatesCache(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Query().Get("object_name") != "orders" {
			t.Fatalf("expected object_name=orders, got %q", r.URL.Query())
		}
		_ = json.NewEncoder(w).Encode(pullResponse{
			OrganizationID: "org1",
			Labels: []labelWire{
				{Driver: "mongo", DatabaseName: "app", ObjectName: "orders", FieldPath: "profile.email", MatchMode: "path", Category: "email_fields", Profile: "full_redact", Source: "manual"},
				{Driver: "mongo", DatabaseName: "app", ObjectName: "orders", FieldPath: "internal_notes", MatchMode: "path", Source: "proposed"},
			},
			Count: 2,
		})
	}))
	defer srv.Close()

	s := New(testConfig(srv.URL), nil)
	objID := "org1:mongo:app:orders"
	labels, err := s.pull(context.Background(), "mongo", "app", "orders")
	if err != nil {
		t.Fatal(err)
	}
	if len(labels) != 1 {
		t.Fatalf("expected only the confirmed label to survive the source filter, got %d", len(labels))
	}
	s.replaceCacheForObject(objID, labels)

	l, ok, err := s.Lookup(context.Background(), objID, "profile.email")
	if err != nil {
		t.Fatal(err)
	}
	if !ok || l.Category != "email_fields" {
		t.Fatalf("expected cached confirmed label, got ok=%v l=%+v", ok, l)
	}
	if _, ok, _ := s.Lookup(context.Background(), objID, "internal_notes"); ok {
		t.Fatal("proposed label must not be cached (pull only returns confirmed labels)")
	}
}

func TestStore_PullHTTPError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer srv.Close()
	s := New(testConfig(srv.URL), nil)
	if _, err := s.pull(context.Background(), "mongo", "app", "orders"); err == nil {
		t.Fatal("expected an error on non-2xx response")
	}
}

func TestStore_ListBySourceOnlyConfirmed(t *testing.T) {
	s := New(testConfig("http://unused"), nil)
	s.replaceCacheForObject("org1:mongo:app:orders", []label.Label{
		{ObjectID: "org1:mongo:app:orders", FieldPath: "a", Source: label.SourceManual},
	})
	out, err := s.ListBySource(context.Background(), "org1:mongo:app:orders", label.SourceManual)
	if err != nil {
		t.Fatal(err)
	}
	if len(out) != 1 {
		t.Fatalf("expected 1 manual label, got %d", len(out))
	}
	if out, _ := s.ListBySource(context.Background(), "org1:mongo:app:orders", label.SourceProposed); out != nil {
		t.Fatal("ListBySource must never return proposed/dismissed — the store never caches them")
	}
}

func TestStore_PutQueuesRatherThanBlocking(t *testing.T) {
	s := New(testConfig("http://unused"), nil)
	start := time.Now()
	if err := s.Put(context.Background(), label.Label{
		ObjectID: "org1:mongo:app:orders", FieldPath: "email", Source: label.SourceProposed, Confidence: 0.7, SampleCount: 1,
	}); err != nil {
		t.Fatal(err)
	}
	if time.Since(start) > 100*time.Millisecond {
		t.Fatal("Put must never block on network I/O")
	}
	batches := s.drainPendingByObject()
	if len(batches["org1:mongo:app:orders"]) != 1 {
		t.Fatalf("expected 1 pending label, got %+v", batches)
	}
}

func TestStore_PutMergesRepeatedObservations(t *testing.T) {
	s := New(testConfig("http://unused"), nil)
	ctx := context.Background()
	l := label.Label{ObjectID: "org1:mongo:app:orders", FieldPath: "email", Source: label.SourceProposed, Confidence: 0.5, SampleCount: 1}
	_ = s.Put(ctx, l)
	l.Confidence = 0.9
	l.SampleCount = 1
	_ = s.Put(ctx, l)

	batches := s.drainPendingByObject()
	got := batches["org1:mongo:app:orders"]
	if len(got) != 1 {
		t.Fatalf("expected one merged pending label, got %d", len(got))
	}
	if got[0].SampleCount != 2 {
		t.Fatalf("expected sample counts summed, got %d", got[0].SampleCount)
	}
	if got[0].Confidence != 0.9 {
		t.Fatalf("expected max confidence retained, got %v", got[0].Confidence)
	}
}

func TestStore_PutIgnoresNonProposedSource(t *testing.T) {
	s := New(testConfig("http://unused"), nil)
	if err := s.Put(context.Background(), label.Label{
		ObjectID: "org1:mongo:app:orders", FieldPath: "email", Source: label.SourceManual,
	}); err != nil {
		t.Fatal(err)
	}
	if batches := s.drainPendingByObject(); len(batches) != 0 {
		t.Fatalf("expected manual-source Put to be dropped, got %+v", batches)
	}
}

func TestStore_PutEvictsLowestConfidenceAtCap(t *testing.T) {
	s := New(testConfig("http://unused"), nil)
	ctx := context.Background()
	// Fill to exactly the cap, with the last entry (field-lowest) at a distinctly lower confidence
	// than the rest so eviction has an unambiguous target.
	for i := 0; i < maxPendingLabels-1; i++ {
		_ = s.Put(ctx, label.Label{
			ObjectID: "org1:mongo:app:orders", FieldPath: "field" + itoa(i), Source: label.SourceProposed, Confidence: 0.5,
		})
	}
	_ = s.Put(ctx, label.Label{ObjectID: "org1:mongo:app:orders", FieldPath: "field-lowest", Source: label.SourceProposed, Confidence: 0.01})
	// A brand-new key at the cap must evict the lowest-confidence entry to make room.
	_ = s.Put(ctx, label.Label{ObjectID: "org1:mongo:app:orders", FieldPath: "newfield", Source: label.SourceProposed, Confidence: 0.99})

	s.mu.RLock()
	n := len(s.pending)
	_, stillHasLowest := s.pending[pendingKey{objectID: "org1:mongo:app:orders", fieldPath: "field-lowest"}]
	_, hasNew := s.pending[pendingKey{objectID: "org1:mongo:app:orders", fieldPath: "newfield"}]
	s.mu.RUnlock()
	if n != maxPendingLabels {
		t.Fatalf("expected pending capped at %d, got %d", maxPendingLabels, n)
	}
	if stillHasLowest {
		t.Fatal("expected the lowest-confidence pending label to be evicted")
	}
	if !hasNew {
		t.Fatal("expected the new label to have been admitted after eviction")
	}
}

func itoa(i int) string {
	if i == 0 {
		return "0"
	}
	neg := i < 0
	if neg {
		i = -i
	}
	var buf [20]byte
	pos := len(buf)
	for i > 0 {
		pos--
		buf[pos] = byte('0' + i%10)
		i /= 10
	}
	if neg {
		pos--
		buf[pos] = '-'
	}
	return string(buf[pos:])
}

func TestStore_FlushPushSendsBatchAndClearsPending(t *testing.T) {
	var mu sync.Mutex
	var got proposeBody
	var calls int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&calls, 1)
		mu.Lock()
		_ = json.NewDecoder(r.Body).Decode(&got)
		mu.Unlock()
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	s := New(testConfig(srv.URL), nil)
	_ = s.Put(context.Background(), label.Label{
		ObjectID: "org1:mongo:app:orders", FieldPath: "email", Source: label.SourceProposed, Confidence: 0.8, SampleCount: 3,
	})
	s.flushPush(context.Background())

	if atomic.LoadInt32(&calls) != 1 {
		t.Fatalf("expected exactly one propose call, got %d", calls)
	}
	mu.Lock()
	defer mu.Unlock()
	if got.Driver != "mongo" || got.DatabaseName != "app" || got.ObjectName != "orders" {
		t.Fatalf("unexpected propose body target: %+v", got)
	}
	if len(got.Labels) != 1 || got.Labels[0].FieldPath != "email" {
		t.Fatalf("unexpected propose body labels: %+v", got.Labels)
	}
	if batches := s.drainPendingByObject(); len(batches) != 0 {
		t.Fatal("expected pending queue drained after a successful flush")
	}
}

func TestStore_FlushPushRetainsBatchOnFailure(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusServiceUnavailable)
	}))
	defer srv.Close()

	s := New(testConfig(srv.URL), nil)
	_ = s.Put(context.Background(), label.Label{
		ObjectID: "org1:mongo:app:orders", FieldPath: "email", Source: label.SourceProposed, Confidence: 0.8, SampleCount: 1,
	})
	s.flushPush(context.Background())

	batches := s.drainPendingByObject()
	if len(batches["org1:mongo:app:orders"]) != 1 {
		t.Fatalf("expected the failed batch to be retained for the next flush, got %+v", batches)
	}
}

func TestStore_LookupNeverBlocksOnNetwork(t *testing.T) {
	// Unreachable URL — Lookup must still return instantly from the local cache without dialing out.
	s := New(testConfig("http://127.0.0.1:1"), nil)
	start := time.Now()
	if _, ok, err := s.Lookup(context.Background(), "org1:mongo:app:orders", "email"); err != nil || ok {
		t.Fatalf("expected a clean cache miss, got ok=%v err=%v", ok, err)
	}
	if time.Since(start) > 50*time.Millisecond {
		t.Fatal("Lookup must never attempt a live HTTP call")
	}
}

var _ label.Store = (*Store)(nil)
