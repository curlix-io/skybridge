// Package label defines the shape of a path-scoped label and a storage-agnostic
// Store interface, for use by internal/mask's path-scoped overlay. Ships only an
// in-memory reference Store (MemStore); a durable backing store is the consumer's
// responsibility.
package label

import (
	"context"
	"fmt"
	"sync"
	"time"
)

// Source identifies how a Label came to exist.
type Source string

const (
	// SourceManual labels are set directly by a human, e.g. through an
	// admin/review surface. They land with full authority immediately.
	SourceManual Source = "manual"
	// SourceProposed labels are detector-suggested and unconfirmed — inert
	// until a steward promotes them to SourceManual.
	SourceProposed Source = "proposed"
	// SourcePlatform labels are a curated default shipped by the consuming
	// application itself, carrying the same authority as SourceManual.
	SourcePlatform Source = "platform"
	// SourceDismissed marks a proposal a steward has explicitly rejected
	// — retained as a negative record so the same proposal isn't
	// resurfaced verbatim on the next scan.
	SourceDismissed Source = "dismissed"
)

// MatchMode selects how FieldPath is interpreted at lookup time.
type MatchMode string

const (
	// MatchPath is an exact resolved-path match — the default and
	// recommended mode for new labels.
	MatchPath MatchMode = "path"
	// MatchKeyAnyDepth matches by bare key name at any depth, independent of
	// path — the legacy behavior this design extends rather than replaces.
	MatchKeyAnyDepth MatchMode = "key_any_depth"
)

// Label is a single path-scoped (or, under MatchKeyAnyDepth, key-scoped) fact
// about a field: what it means (Category), and optionally what to do about it
// (Profile).
type Label struct {
	// ObjectID is an opaque identifier for the collection/table this label
	// applies to. It MUST already encode tenant scoping if a Store instance
	// is shared across tenants — this package does not add or enforce a tenant
	// dimension of its own.
	ObjectID string
	// FieldPath is the resolved path this label applies to, e.g.
	// "profile.contact.email", or a bare key name under MatchKeyAnyDepth.
	FieldPath string
	MatchMode MatchMode
	// Category is a consumer-defined classification, e.g. "email_fields".
	Category string
	// Profile is a consumer-defined action hint, e.g. "full_redact",
	// "partial_mask", "do_not_mask". Optional — a consumer using Label for
	// something other than redaction may leave this empty.
	Profile string
	Source  Source
	// Confidence is set when Source == SourceProposed; zero-value for
	// manual/platform/dismissed labels.
	Confidence float64
	// SampleCount is how many observed documents support this label.
	SampleCount int
	// LastObservedAt is bumped by the proposal engine whenever a document
	// containing FieldPath is walked — distinct from UpdatedAt,
	// which tracks label edits, not data observation. Zero value means
	// never observed by a scan (e.g. a purely manual label).
	LastObservedAt time.Time
	UpdatedAt      time.Time
	UpdatedBy      string
}

func (l Label) key() labelKey {
	return labelKey{ObjectID: l.ObjectID, FieldPath: l.FieldPath}
}

// labelKey is (ObjectID, FieldPath) only, not MatchMode — a given path
// string denotes one label regardless of mode; MatchMode records how that
// label's FieldPath should be interpreted by a caller, it doesn't
// create a second, independent slot for the same path.
type labelKey struct {
	ObjectID  string
	FieldPath string
}

// Store is the storage-agnostic interface pathlabel consumers implement (or
// use MemStore for) to persist and query labels. Implementations MUST be safe
// for concurrent use by multiple goroutines: Lookup runs on every document
// walked at redact time, so callers will call it concurrently across parallel
// document/leaf processing without additional locking on their end.
type Store interface {
	// Lookup returns the label stored under the exact (objectID, fieldPath)
	// key, if one exists — a Label's own MatchMode field records how it was
	// intended to be matched, but Lookup itself does no mode-specific
	// interpretation. A caller implementing an ordered fallback (path match,
	// then bare-key match, then a value-shape safety net) issues one
	// Lookup call per mode it wants to try, varying fieldPath accordingly:
	// first the leaf's full resolved path, then (on a miss) its bare key.
	Lookup(ctx context.Context, objectID, fieldPath string) (Label, bool, error)
	// Put upserts l. For l.Source == SourceProposed, Put MUST merge with any
	// existing proposed row at the same key rather than overwrite it:
	// SampleCount accumulates, Confidence takes the higher of the two,
	// LastObservedAt/UpdatedAt take the later timestamp. For any
	// other Source, Put is last-write-wins, since those represent an
	// explicit human/curated decision, not an accumulating signal.
	Put(ctx context.Context, l Label) error
	// ListBySource returns all labels for objectID with the given Source.
	ListBySource(ctx context.Context, objectID string, source Source) ([]Label, error)
}

// MemStore is an in-memory, non-durable reference Store implementation
// intended for tests and small/standalone use. It is safe for
// concurrent use.
type MemStore struct {
	mu     sync.RWMutex
	labels map[labelKey]Label
}

// NewMemStore returns an empty, ready-to-use MemStore.
func NewMemStore() *MemStore {
	return &MemStore{labels: make(map[labelKey]Label)}
}

func (s *MemStore) Lookup(_ context.Context, objectID, fieldPath string) (Label, bool, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	l, ok := s.labels[labelKey{ObjectID: objectID, FieldPath: fieldPath}]
	return l, ok, nil
}

func (s *MemStore) Put(_ context.Context, l Label) error {
	if l.ObjectID == "" || l.FieldPath == "" {
		return fmt.Errorf("label: ObjectID and FieldPath are required")
	}
	if l.MatchMode == "" {
		l.MatchMode = MatchPath
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	k := l.key()
	existing, ok := s.labels[k]
	if ok && l.Source == SourceProposed && existing.Source == SourceProposed {
		l = mergeProposed(existing, l)
	}
	s.labels[k] = l
	return nil
}

func mergeProposed(existing, incoming Label) Label {
	merged := incoming
	merged.SampleCount = existing.SampleCount + incoming.SampleCount
	if existing.Confidence > merged.Confidence {
		merged.Confidence = existing.Confidence
	}
	if existing.LastObservedAt.After(merged.LastObservedAt) {
		merged.LastObservedAt = existing.LastObservedAt
	}
	if existing.UpdatedAt.After(merged.UpdatedAt) {
		merged.UpdatedAt = existing.UpdatedAt
	}
	return merged
}

func (s *MemStore) ListBySource(_ context.Context, objectID string, source Source) ([]Label, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	var out []Label
	for _, l := range s.labels {
		if l.ObjectID == objectID && l.Source == source {
			out = append(out, l)
		}
	}
	return out, nil
}

var _ Store = (*MemStore)(nil)
