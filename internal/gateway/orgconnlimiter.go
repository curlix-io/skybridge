package gateway

import (
	"errors"
	"sync"
)

// ErrOrgConnLimitReached is returned when an org has reached its concurrent-connection ceiling.
var ErrOrgConnLimitReached = errors.New("gateway: organization concurrent connection limit reached")

// OrgConnLimiter caps how many client connections one org can have relayed *simultaneously*
// through this gateway. Unlike ConnRateLimiter (which only throttles the *rate* of new connections
// per minute), this bounds the standing total — without it, one org can open connections at or
// below its per-minute rate limit and simply never close them, holding goroutines, file
// descriptors, and tunnel-session stream slots indefinitely at every other org's expense.
//
// Acquire reserves a slot for orgID, reporting false (no slot reserved) if the org is already at
// its limit. Every successful Acquire must be paired with exactly one Release once that connection
// ends.
type OrgConnLimiter interface {
	Acquire(orgID string) bool
	Release(orgID string)
}

// NoopOrgConnLimiter allows unlimited concurrent connections per org (the default).
type NoopOrgConnLimiter struct{}

// Acquire implements OrgConnLimiter.
func (NoopOrgConnLimiter) Acquire(string) bool { return true }

// Release implements OrgConnLimiter.
func (NoopOrgConnLimiter) Release(string) {}

type orgConnLimiter struct {
	max int

	mu     sync.Mutex
	counts map[string]int
}

// NewOrgConnLimiter returns a limiter capping each org at max concurrent connections, or nil when
// max <= 0 (unlimited) — callers should treat a nil OrgConnLimiter as NoopOrgConnLimiter (every
// method here is nil-receiver-safe, matching NewConnRateLimiter's established pattern).
func NewOrgConnLimiter(max int) OrgConnLimiter {
	if max <= 0 {
		return nil
	}
	return &orgConnLimiter{max: max, counts: make(map[string]int)}
}

// Acquire implements OrgConnLimiter.
func (l *orgConnLimiter) Acquire(orgID string) bool {
	if l == nil {
		return true
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.counts[orgID] >= l.max {
		return false
	}
	l.counts[orgID]++
	return true
}

// Release implements OrgConnLimiter.
func (l *orgConnLimiter) Release(orgID string) {
	if l == nil {
		return
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.counts[orgID] <= 0 {
		return
	}
	l.counts[orgID]--
	if l.counts[orgID] == 0 {
		// Drop the entry rather than leaving a zero-count key behind — keeps the map bounded by
		// the number of orgs *currently* holding a connection, not every org ever seen.
		delete(l.counts, orgID)
	}
}
