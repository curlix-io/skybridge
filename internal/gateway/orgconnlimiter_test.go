package gateway

import "testing"

func TestOrgConnLimiterAcquireUpToLimit(t *testing.T) {
	lim := NewOrgConnLimiter(2)

	if !lim.Acquire("org-a") {
		t.Fatal("expected first Acquire to succeed")
	}
	if !lim.Acquire("org-a") {
		t.Fatal("expected second Acquire to succeed")
	}
	if lim.Acquire("org-a") {
		t.Fatal("expected third Acquire to be refused once at the limit")
	}
	// A different org has its own independent budget.
	if !lim.Acquire("org-b") {
		t.Fatal("expected org-b's first Acquire to succeed independently of org-a's limit")
	}
}

// TestOrgConnLimiterReleaseFreesASlot is the core regression test: without Release actually
// freeing a slot, an org that reached its limit once would be stuck rejected forever, even after
// every one of its earlier connections legitimately closed.
func TestOrgConnLimiterReleaseFreesASlot(t *testing.T) {
	lim := NewOrgConnLimiter(1)

	if !lim.Acquire("org-a") {
		t.Fatal("expected first Acquire to succeed")
	}
	if lim.Acquire("org-a") {
		t.Fatal("expected second Acquire to be refused at the limit")
	}
	lim.Release("org-a")
	if !lim.Acquire("org-a") {
		t.Fatal("expected Acquire to succeed again after Release freed the slot")
	}
}

func TestOrgConnLimiterReleaseWithoutAcquireIsHarmless(t *testing.T) {
	lim := NewOrgConnLimiter(1)
	// Must not panic or go negative in a way that lets the org over-acquire afterward.
	lim.Release("org-a")
	if !lim.Acquire("org-a") {
		t.Fatal("expected Acquire to succeed normally after a spurious Release")
	}
	if lim.Acquire("org-a") {
		t.Fatal("expected the limit to still be enforced after a spurious Release")
	}
}

func TestNewOrgConnLimiterNilWhenDisabled(t *testing.T) {
	if NewOrgConnLimiter(0) != nil {
		t.Fatal("expected nil limiter when max <= 0")
	}
	if NewOrgConnLimiter(-1) != nil {
		t.Fatal("expected nil limiter when max is negative")
	}
}

// TestNilOrgConnLimiterIsUnlimited confirms a nil *orgConnLimiter (the typed-nil an OrgConnLimiter
// variable holds when NewOrgConnLimiter returned nil) behaves like NoopOrgConnLimiter rather than
// panicking — Acquire/Release must be safe to call on it directly, matching NewConnRateLimiter's
// established nil-receiver-safe pattern.
func TestNilOrgConnLimiterIsUnlimited(t *testing.T) {
	var lim *orgConnLimiter
	if !lim.Acquire("org-a") {
		t.Fatal("expected a nil limiter to always allow Acquire")
	}
	lim.Release("org-a") // must not panic
}

func TestNoopOrgConnLimiterAlwaysAllows(t *testing.T) {
	var lim NoopOrgConnLimiter
	for i := 0; i < 1000; i++ {
		if !lim.Acquire("org-a") {
			t.Fatal("expected NoopOrgConnLimiter to always allow Acquire")
		}
	}
	lim.Release("org-a") // must not panic
}
