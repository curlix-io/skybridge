package dbexec

import (
	"crypto/sha256"
	"encoding/hex"
	"sync"
	"time"

	"github.com/curlix-io/skybridge/internal/edge"
)

// idempotencyCache dedups db_execute_write calls carrying an "idempotency_key" arg — a retry of
// the same key returns the first call's result instead of re-executing the write, mirroring the
// dry_run + Idempotency-Key contract root CLAUDE.md's "Input validation" section requires for
// sensitive writes. Bounded (TTL + max-entries oldest-eviction), same shape as the KMS decrypt
// cache pattern (see curlix CLAUDE.md's CURLIX_KMS_DECRYPT_CACHE_* vars) — an in-memory cache
// scoped to this one connector process, not shared across connectors or persisted across restarts
// (a restart just means the next retry after a restart re-executes once, which is the same
// fail-safe behavior as a cache miss).
type idempotencyCache struct {
	mu         sync.Mutex
	entries    map[string]idempotencyEntry
	order      []string // insertion order, oldest first, for FIFO eviction
	ttl        time.Duration
	maxEntries int
}

type idempotencyEntry struct {
	requestHash string
	result      edge.Result
	expiresAt   time.Time
}

const (
	defaultIdempotencyTTL        = 10 * time.Minute
	defaultIdempotencyMaxEntries = 2000
)

func newIdempotencyCache(ttl time.Duration, maxEntries int) *idempotencyCache {
	if ttl <= 0 {
		ttl = defaultIdempotencyTTL
	}
	if maxEntries <= 0 {
		maxEntries = defaultIdempotencyMaxEntries
	}
	return &idempotencyCache{
		entries:    make(map[string]idempotencyEntry),
		ttl:        ttl,
		maxEntries: maxEntries,
	}
}

// requestHash fingerprints the parts of a db_execute_write call that must match for a repeated
// idempotency key to be considered the same logical request — dbType/database/statement, not the
// idempotency key itself. A key reused with different content is a caller bug (or key collision),
// not a legitimate retry, and get() surfaces that as a conflict rather than silently returning a
// stale result for the wrong statement.
func requestHash(dbType, database, statement string) string {
	sum := sha256.Sum256([]byte(dbType + "\x00" + database + "\x00" + statement))
	return hex.EncodeToString(sum[:])
}

// get returns the cached result for key if present, not expired, and requestHash matches — along
// with a conflict flag set when key exists but requestHash differs (caller must reject the call
// rather than execute it or return the mismatched cached result).
func (c *idempotencyCache) get(key, wantHash string) (result edge.Result, hit bool, conflict bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	entry, ok := c.entries[key]
	if !ok {
		return nil, false, false
	}
	if time.Now().After(entry.expiresAt) {
		delete(c.entries, key)
		return nil, false, false
	}
	if entry.requestHash != wantHash {
		return nil, false, true
	}
	return entry.result, true, false
}

// put stores result under key, evicting the oldest entry first if this insert would exceed
// maxEntries. Overwriting an existing key (same key, same requestHash re-verified by the caller's
// prior get()) does not grow order — this only appends for genuinely new keys.
func (c *idempotencyCache) put(key, hash string, result edge.Result) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if _, exists := c.entries[key]; !exists {
		if len(c.order) >= c.maxEntries {
			oldest := c.order[0]
			c.order = c.order[1:]
			delete(c.entries, oldest)
		}
		c.order = append(c.order, key)
	}
	c.entries[key] = idempotencyEntry{
		requestHash: hash,
		result:      result,
		expiresAt:   time.Now().Add(c.ttl),
	}
}
