package dbexec

import (
	"testing"
	"time"

	"github.com/curlix-io/skybridge/internal/edge"
)

func TestIdempotencyCacheMissThenHit(t *testing.T) {
	c := newIdempotencyCache(time.Minute, 10)
	if _, hit, conflict := c.get("k1", "h1"); hit || conflict {
		t.Fatalf("expected miss on empty cache, got hit=%v conflict=%v", hit, conflict)
	}
	want := edge.Result{"ok": true}
	c.put("k1", "h1", want)
	got, hit, conflict := c.get("k1", "h1")
	if !hit || conflict {
		t.Fatalf("expected hit, no conflict, got hit=%v conflict=%v", hit, conflict)
	}
	if got["ok"] != true {
		t.Fatalf("expected cached result returned, got %+v", got)
	}
}

func TestIdempotencyCacheConflictOnDifferentHash(t *testing.T) {
	c := newIdempotencyCache(time.Minute, 10)
	c.put("k1", "h1", edge.Result{"ok": true})
	if _, hit, conflict := c.get("k1", "different-hash"); hit || !conflict {
		t.Fatalf("expected conflict (not hit) for mismatched hash, got hit=%v conflict=%v", hit, conflict)
	}
}

func TestIdempotencyCacheExpiredEntryIsMiss(t *testing.T) {
	c := newIdempotencyCache(1*time.Millisecond, 10)
	c.put("k1", "h1", edge.Result{"ok": true})
	time.Sleep(5 * time.Millisecond)
	if _, hit, conflict := c.get("k1", "h1"); hit || conflict {
		t.Fatalf("expected a miss for an expired entry, got hit=%v conflict=%v", hit, conflict)
	}
}

func TestIdempotencyCacheEvictsOldestOverCapacity(t *testing.T) {
	c := newIdempotencyCache(time.Minute, 2)
	c.put("k1", "h1", edge.Result{"n": 1})
	c.put("k2", "h2", edge.Result{"n": 2})
	c.put("k3", "h3", edge.Result{"n": 3}) // k1 should be evicted, over capacity 2

	if _, hit, _ := c.get("k1", "h1"); hit {
		t.Fatal("expected k1 to have been evicted as the oldest entry")
	}
	if _, hit, _ := c.get("k2", "h2"); !hit {
		t.Fatal("expected k2 to survive eviction")
	}
	if _, hit, _ := c.get("k3", "h3"); !hit {
		t.Fatal("expected k3 (just inserted) to be present")
	}
}

func TestIdempotencyCacheOverwriteSameKeyDoesNotGrowOrder(t *testing.T) {
	c := newIdempotencyCache(time.Minute, 2)
	c.put("k1", "h1", edge.Result{"n": 1})
	c.put("k1", "h1", edge.Result{"n": 2}) // same key -- overwrite, not a new insertion
	c.put("k2", "h2", edge.Result{"n": 3})
	// Capacity is 2 and only k1/k2 were ever genuinely inserted -- neither should be evicted.
	if _, hit, _ := c.get("k1", "h1"); !hit {
		t.Fatal("expected k1 to survive (overwrite must not count as a second insertion)")
	}
	got, _, _ := c.get("k1", "h1")
	if got["n"] != 2 {
		t.Fatalf("expected overwritten value, got %+v", got)
	}
}

func TestRequestHashDeterministicAndDistinguishesInputs(t *testing.T) {
	h1 := requestHash("postgres", "app", "DELETE FROM t")
	h2 := requestHash("postgres", "app", "DELETE FROM t")
	if h1 != h2 {
		t.Fatal("expected requestHash to be deterministic for identical inputs")
	}
	if requestHash("postgres", "app", "DELETE FROM t2") == h1 {
		t.Fatal("expected a different statement to produce a different hash")
	}
	if requestHash("mysql", "app", "DELETE FROM t") == h1 {
		t.Fatal("expected a different db_type to produce a different hash")
	}
}
