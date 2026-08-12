package remotestore

import (
	"bytes"
	"context"
	"encoding/json"
	"log/slog"
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

func TestNew_FloorsPollAndPushIntervals(t *testing.T) {
	cfg := config.Agent{
		PathLabelURL:         "http://unused",
		OrgID:                "org1",
		PathLabelPollSeconds: 1, // below minPollSeconds
		PathLabelPushSeconds: 1, // below minPushSeconds
	}
	s := New(cfg, nil)
	if s.pollInterval != minPollSeconds*time.Second {
		t.Fatalf("expected poll interval floored to %v, got %v", minPollSeconds*time.Second, s.pollInterval)
	}
	if s.pushInterval != minPushSeconds*time.Second {
		t.Fatalf("expected push interval floored to %v, got %v", minPushSeconds*time.Second, s.pushInterval)
	}
	if s.logger == nil {
		t.Fatal("expected New(..., nil) to default the logger rather than leave it nil")
	}
}

func TestNew_KeepsIntervalsAboveFloor(t *testing.T) {
	cfg := config.Agent{
		PathLabelURL:         "http://unused",
		PathLabelPollSeconds: 3600,
		PathLabelPushSeconds: 120,
	}
	s := New(cfg, nil)
	if s.pollInterval != 3600*time.Second {
		t.Fatalf("expected poll interval to pass through unfloored, got %v", s.pollInterval)
	}
	if s.pushInterval != 120*time.Second {
		t.Fatalf("expected push interval to pass through unfloored, got %v", s.pushInterval)
	}
}

func TestObjectParts_RejectsTooFewSegments(t *testing.T) {
	if _, _, _, ok := objectParts("only:three:parts"); ok {
		t.Fatal("expected objectParts to reject an objectID with fewer than 4 ':'-separated parts")
	}
	if _, _, _, ok := objectParts(""); ok {
		t.Fatal("expected objectParts to reject an empty objectID")
	}
}

func TestObjectParts_TakesLastThreeSegments(t *testing.T) {
	driver, db, obj, ok := objectParts("org:with:colons:mongo:app:orders")
	if !ok {
		t.Fatal("expected a 4+-segment objectID to parse")
	}
	if driver != "mongo" || db != "app" || obj != "orders" {
		t.Fatalf("expected last 3 segments regardless of extra ':' earlier, got driver=%q db=%q obj=%q", driver, db, obj)
	}
}

func TestStore_PutRejectsMissingObjectIDOrFieldPath(t *testing.T) {
	s := New(testConfig("http://unused"), nil)
	if err := s.Put(context.Background(), label.Label{FieldPath: "email", Source: label.SourceProposed}); err == nil {
		t.Fatal("expected an error when ObjectID is empty")
	}
	if err := s.Put(context.Background(), label.Label{ObjectID: "org1:mongo:app:orders", Source: label.SourceProposed}); err == nil {
		t.Fatal("expected an error when FieldPath is empty")
	}
}

func TestStore_PutDefaultsMatchMode(t *testing.T) {
	s := New(testConfig("http://unused"), nil)
	_ = s.Put(context.Background(), label.Label{
		ObjectID: "org1:mongo:app:orders", FieldPath: "email", Source: label.SourceProposed,
	})
	batches := s.drainPendingByObject()
	got := batches["org1:mongo:app:orders"]
	if len(got) != 1 || got[0].MatchMode != label.MatchPath {
		t.Fatalf("expected MatchMode to default to label.MatchPath, got %+v", got)
	}
}

func TestMergeProposed_KeepsEarlierLastObservedAtIfLater(t *testing.T) {
	earlier := time.Now().Add(-time.Hour)
	later := time.Now()
	existing := label.Label{SampleCount: 2, Confidence: 0.3, LastObservedAt: later}
	incoming := label.Label{SampleCount: 1, Confidence: 0.9, LastObservedAt: earlier}
	merged := mergeProposed(existing, incoming)
	if merged.SampleCount != 3 {
		t.Fatalf("expected summed sample count, got %d", merged.SampleCount)
	}
	if merged.Confidence != 0.9 {
		t.Fatalf("expected higher confidence retained, got %v", merged.Confidence)
	}
	if !merged.LastObservedAt.Equal(later) {
		t.Fatalf("expected the later LastObservedAt to win even though it belonged to 'existing', got %v", merged.LastObservedAt)
	}
}

func TestStore_SeedObjectTracksObjectForPull(t *testing.T) {
	s := New(testConfig("http://unused"), nil)
	if ids := s.knownObjectIDs(); len(ids) != 0 {
		t.Fatalf("expected no known objects before seeding, got %v", ids)
	}
	s.SeedObject("org1:mongo:app:orders")
	ids := s.knownObjectIDs()
	if len(ids) != 1 || ids[0] != "org1:mongo:app:orders" {
		t.Fatalf("expected SeedObject to register the object for pull, got %v", ids)
	}
	// Seeding twice must not create a duplicate cache entry / duplicate known-object.
	s.SeedObject("org1:mongo:app:orders")
	if ids := s.knownObjectIDs(); len(ids) != 1 {
		t.Fatalf("expected SeedObject to be idempotent, got %v", ids)
	}
	// A seeded placeholder must never satisfy a real Lookup.
	if _, ok, _ := s.Lookup(context.Background(), "org1:mongo:app:orders", "email"); ok {
		t.Fatal("expected the seed placeholder to never match a real field-path lookup")
	}
}

func TestStore_SeedObjectIgnoresEmpty(t *testing.T) {
	s := New(testConfig("http://unused"), nil)
	s.SeedObject("")
	if ids := s.knownObjectIDs(); len(ids) != 0 {
		t.Fatalf("expected empty objectID to be ignored, got %v", ids)
	}
}

func TestStore_KnownObjectIDsIncludesPendingAndCache(t *testing.T) {
	s := New(testConfig("http://unused"), nil)
	_ = s.Put(context.Background(), label.Label{
		ObjectID: "org1:mongo:app:orders", FieldPath: "email", Source: label.SourceProposed,
	})
	s.replaceCacheForObject("org1:mongo:app:users", []label.Label{
		{ObjectID: "org1:mongo:app:users", FieldPath: "name", Source: label.SourceManual},
	})
	ids := s.knownObjectIDs()
	seen := map[string]bool{}
	for _, id := range ids {
		seen[id] = true
	}
	if !seen["org1:mongo:app:orders"] || !seen["org1:mongo:app:users"] {
		t.Fatalf("expected knownObjectIDs to include both pending and cached objects, got %v", ids)
	}
}

func TestStore_RefreshPullUpdatesCacheForKnownObjects(t *testing.T) {
	var calls int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&calls, 1)
		_ = json.NewEncoder(w).Encode(pullResponse{
			Labels: []labelWire{
				{FieldPath: "email", MatchMode: "path", Category: "email_fields", Source: "manual"},
			},
		})
	}))
	defer srv.Close()

	s := New(testConfig(srv.URL), nil)
	s.SeedObject("org1:mongo:app:orders")
	s.refreshPull(context.Background())

	if atomic.LoadInt32(&calls) != 1 {
		t.Fatalf("expected exactly one pull call for the seeded object, got %d", calls)
	}
	l, ok, err := s.Lookup(context.Background(), "org1:mongo:app:orders", "email")
	if err != nil {
		t.Fatal(err)
	}
	if !ok || l.Category != "email_fields" {
		t.Fatalf("expected refreshPull to populate the cache, got ok=%v l=%+v", ok, l)
	}
}

func TestStore_RefreshPullLogsAndContinuesOnError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer srv.Close()

	s := New(testConfig(srv.URL), nil)
	s.SeedObject("org1:mongo:app:orders")
	// Must not panic and must leave the cache untouched (aside from the seed placeholder) on pull failure.
	s.refreshPull(context.Background())
	if _, ok, _ := s.Lookup(context.Background(), "org1:mongo:app:orders", "email"); ok {
		t.Fatal("expected no cache entry to appear from a failed pull")
	}
}

func TestStore_RefreshPullSkipsObjectsWithBadIDFormat(t *testing.T) {
	s := New(testConfig("http://unused"), nil)
	s.SeedObject("not-enough-parts")
	// Should not panic despite an unparseable objectID.
	s.refreshPull(context.Background())
}

func TestStore_ReplaceCacheForObjectOverwritesPriorEntries(t *testing.T) {
	s := New(testConfig("http://unused"), nil)
	objID := "org1:mongo:app:orders"
	s.replaceCacheForObject(objID, []label.Label{
		{ObjectID: objID, FieldPath: "a", Source: label.SourceManual, Category: "old"},
	})
	s.replaceCacheForObject(objID, []label.Label{
		{ObjectID: objID, FieldPath: "b", Source: label.SourceManual, Category: "new"},
	})
	if _, ok, _ := s.Lookup(context.Background(), objID, "a"); ok {
		t.Fatal("expected the stale field 'a' to be evicted when the object's labels were replaced")
	}
	l, ok, _ := s.Lookup(context.Background(), objID, "b")
	if !ok || l.Category != "new" {
		t.Fatalf("expected the new field 'b' to be cached, got ok=%v l=%+v", ok, l)
	}
}

func TestStore_RestorePendingMergesWithExisting(t *testing.T) {
	s := New(testConfig("http://unused"), nil)
	ctx := context.Background()
	_ = s.Put(ctx, label.Label{
		ObjectID: "org1:mongo:app:orders", FieldPath: "email", Source: label.SourceProposed, Confidence: 0.4, SampleCount: 1,
	})
	// Simulate a failed flush restoring an overlapping observation.
	s.restorePending("org1:mongo:app:orders", []label.Label{
		{ObjectID: "org1:mongo:app:orders", FieldPath: "email", Source: label.SourceProposed, Confidence: 0.9, SampleCount: 2},
	})
	batches := s.drainPendingByObject()
	got := batches["org1:mongo:app:orders"]
	if len(got) != 1 || got[0].SampleCount != 3 {
		t.Fatalf("expected restorePending to merge with the existing pending entry, got %+v", got)
	}
}

func TestStore_PushPropagatesTransportError(t *testing.T) {
	s := New(testConfig("http://127.0.0.1:1"), nil)
	err := s.push(context.Background(), "mongo", "app", "orders", []label.Label{
		{FieldPath: "email", Source: label.SourceProposed},
	})
	if err == nil {
		t.Fatal("expected push to a dead endpoint to return an error")
	}
}

func TestStore_FlushPushSkipsBadObjectID(t *testing.T) {
	s := New(testConfig("http://unused"), nil)
	// Insert a pending entry directly under a malformed objectID so drainPendingByObject groups it,
	// but objectParts rejects it in flushPush — must not panic, and must not retain it either.
	s.mu.Lock()
	s.pending[pendingKey{objectID: "bad-id", fieldPath: "x"}] = label.Label{ObjectID: "bad-id", FieldPath: "x", Source: label.SourceProposed}
	s.mu.Unlock()
	s.flushPush(context.Background())
	if batches := s.drainPendingByObject(); len(batches) != 0 {
		t.Fatalf("expected the malformed-objectID pending entry to be dropped, not retained, got %+v", batches)
	}
}

func TestStore_StartPullsImmediatelyAndStopsOnCancel(t *testing.T) {
	var calls int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&calls, 1)
		_ = json.NewEncoder(w).Encode(pullResponse{})
	}))
	defer srv.Close()

	cfg := testConfig(srv.URL)
	s := New(cfg, nil)
	s.SeedObject("org1:mongo:app:orders")

	ctx, cancel := context.WithCancel(context.Background())
	s.Start(ctx)
	// Start does a synchronous refreshPull before spawning the background loops.
	if atomic.LoadInt32(&calls) < 1 {
		t.Fatal("expected Start to perform an immediate pull")
	}

	// Exercise the push loop's flush-on-cancel path too.
	_ = s.Put(context.Background(), label.Label{
		ObjectID: "org1:mongo:app:orders", FieldPath: "email", Source: label.SourceProposed, Confidence: 0.5, SampleCount: 1,
	})
	cancel()
	// Give the goroutines a moment to observe cancellation and flush.
	time.Sleep(100 * time.Millisecond)
}

var _ label.Store = (*Store)(nil)

// TestStore_RecoverBackgroundStopsPanicAndLogs is the regression test for Start's background
// pull/push loops' panic safety net: a panic triggered by a malformed or adversarial
// control-plane response must stop only that one sync loop, not crash the whole agent process
// and every live database session sharing it.
func TestStore_RecoverBackgroundStopsPanicAndLogs(t *testing.T) {
	var buf bytes.Buffer
	s := New(testConfig("http://127.0.0.1:0"), slog.New(slog.NewTextHandler(&buf, nil)))

	func() {
		defer s.recoverBackground("test sync loop")
		panic("simulated parsing bug on a malformed control-plane response")
	}()

	if !bytes.Contains(buf.Bytes(), []byte("recovered from panic in test sync loop")) {
		t.Fatalf("expected a recovered-panic log line naming the loop, got %q", buf.String())
	}
}

func TestStore_RecoverBackgroundNoopWithoutPanic(t *testing.T) {
	var buf bytes.Buffer
	s := New(testConfig("http://127.0.0.1:0"), slog.New(slog.NewTextHandler(&buf, nil)))

	func() {
		defer s.recoverBackground("test sync loop")
	}()

	if buf.Len() != 0 {
		t.Fatalf("expected no log output absent a panic, got %q", buf.String())
	}
}
