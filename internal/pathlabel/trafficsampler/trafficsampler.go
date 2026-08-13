// Package trafficsampler supplies aiclassifier.Sampler samples from live wire-proxy/dbquery
// traffic that is already flowing through the agent/edge process, instead of a scan job dialing a
// second, dedicated read-only DSN against the source database. See
// docs/AI_PATH_LABELLING_DESIGN.md §5.2 for the design this implements: the same shape as an inline
// proxy classifying "as data traverses the proxy... no periodic scan and no separate database
// credential" (§4b).
//
// Buffer is fed by Observe, called from the same pre-mask hot-path call sites that already resolve
// a row/leaf's ObjectID/FieldPath for PathOverlay (internal/edge/dbquery/mask.go's proposeLeaf call
// sites today; the wire engines' own PathOverlay resolution points are the natural next callers).
// Observe never blocks and never errors — a sample that can't be buffered (buffer full, empty
// value) is silently dropped, matching the "never touch or slow the live session" rule in
// docs/AI_PATH_LABELLING_DESIGN.md §5.5. Buffer never persists a sample to disk or sends it
// anywhere except into a Classifier call made by the caller's own Scanner.
package trafficsampler

import (
	"container/list"
	"context"
	"sync"

	"github.com/curlix-io/skybridge/internal/pathlabel/aiclassifier"
)

// Buffer is a bounded, in-memory cache of recently-observed sample values per (ObjectID,
// FieldPath), implementing aiclassifier.Sampler so a Scanner can classify directly against it —
// no database dial of its own. Zero value is not usable; call New.
type Buffer struct {
	mu         sync.Mutex
	maxFields  int
	maxSamples int
	samples    map[string][]string
	lru        *list.List
	elems      map[string]*list.Element
}

// New returns a ready-to-use Buffer. maxFields bounds how many distinct (ObjectID, FieldPath) pairs
// are tracked at once, evicting the least-recently-observed field once the cap is hit — a fixed
// memory ceiling regardless of how many tables/columns live traffic touches. maxSamplesPerField
// bounds how many values are retained per field, matching aiclassifier.Scanner's own MaxSamples
// shape. Both fall back to a sane default when <= 0.
func New(maxFields, maxSamplesPerField int) *Buffer {
	if maxFields <= 0 {
		maxFields = 10000
	}
	if maxSamplesPerField <= 0 {
		maxSamplesPerField = 20
	}
	return &Buffer{
		maxFields:  maxFields,
		maxSamples: maxSamplesPerField,
		samples:    make(map[string][]string),
		lru:        list.New(),
		elems:      make(map[string]*list.Element),
	}
}

func fieldKey(objectID, fieldPath string) string {
	return objectID + "\x00" + fieldPath
}

// Observe records value as a sample for (objectID, fieldPath). A blank objectID, fieldPath, or
// value is dropped rather than buffered — an empty value carries no classification signal, and an
// empty identity can't be scanned back out by Sample. Safe for concurrent use from multiple wire
// sessions at once.
func (b *Buffer) Observe(objectID, fieldPath, value string) {
	if objectID == "" || fieldPath == "" || value == "" {
		return
	}
	key := fieldKey(objectID, fieldPath)
	b.mu.Lock()
	defer b.mu.Unlock()

	if elem, ok := b.elems[key]; ok {
		b.lru.MoveToFront(elem)
	} else {
		if len(b.samples) >= b.maxFields {
			b.evictOldest()
		}
		b.elems[key] = b.lru.PushFront(key)
	}
	if vals := b.samples[key]; len(vals) < b.maxSamples {
		b.samples[key] = append(vals, value)
	}
}

// evictOldest drops the least-recently-observed field. Caller must hold b.mu.
func (b *Buffer) evictOldest() {
	oldest := b.lru.Back()
	if oldest == nil {
		return
	}
	key := oldest.Value.(string)
	b.lru.Remove(oldest)
	delete(b.elems, key)
	delete(b.samples, key)
}

// Sample implements aiclassifier.Sampler by returning up to maxSamples of the values already
// buffered for (objectID, fieldPath) — ok=false when nothing has been observed yet, e.g. a field a
// scan cycle knows about (via Fields) but that hasn't produced a fresh sample since its last
// eviction. Never dials out or blocks; this is a pure in-memory lookup.
func (b *Buffer) Sample(_ context.Context, objectID, fieldPath string, maxSamples int) ([]string, bool) {
	key := fieldKey(objectID, fieldPath)
	b.mu.Lock()
	defer b.mu.Unlock()

	vals := b.samples[key]
	if len(vals) == 0 {
		return nil, false
	}
	if maxSamples > 0 && len(vals) > maxSamples {
		vals = vals[:maxSamples]
	}
	out := make([]string, len(vals))
	copy(out, vals)
	return out, true
}

// Fields returns every (ObjectID, FieldPath) currently holding at least one buffered sample, for a
// scan loop to classify — replacing a catalog/information_schema crawl as the discovery mechanism
// (docs/AI_PATH_LABELLING_DESIGN.md §5.2's "discovery is traffic, not a schema scan" tradeoff: a
// table/column with no query traffic simply won't appear here until something queries it).
func (b *Buffer) Fields() []aiclassifier.Field {
	b.mu.Lock()
	defer b.mu.Unlock()

	fields := make([]aiclassifier.Field, 0, len(b.samples))
	for key := range b.samples {
		objectID, fieldPath := splitFieldKey(key)
		fields = append(fields, aiclassifier.Field{ObjectID: objectID, FieldPath: fieldPath})
	}
	return fields
}

func splitFieldKey(key string) (objectID, fieldPath string) {
	for i := 0; i < len(key); i++ {
		if key[i] == '\x00' {
			return key[:i], key[i+1:]
		}
	}
	return key, ""
}
