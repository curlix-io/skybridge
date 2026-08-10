// Package aiclassifier proposes label.Label values for table columns / document fields using both
// the field's name and a sample of its values, independent of live query traffic. It is a second,
// independent producer into label.Store's existing propose/confirm contract — see
// docs/AI_PATH_LABELLING_DESIGN.md for the full design. It never redacts anything itself and never
// runs on the query hot path; a Scanner is meant to be driven by a periodic job, separate from any
// live database session.
package aiclassifier

import (
	"context"
	"time"

	"github.com/curlix-io/skybridge/internal/pathlabel/label"
)

// Classifier proposes a label for one field given its identity and a bounded sample of its values.
// ok=false means "no confident proposal" — a low-signal or empty sample, a taxonomy miss, or a
// backend failure are all indistinguishable to the caller, mirroring mask.Remote.Detect's contract:
// a failure to classify must never itself become a false-positive proposal.
//
// Implementations are interchangeable behind this one interface — an LLM-API-backed classifier
// (NewLLM, this package) and a self-hosted fine-tuned-NER classifier are both valid backends; the
// choice is a deployment decision, not an architectural one. See
// docs/AI_PATH_LABELLING_DESIGN.md §5.1a/§5.1b.
type Classifier interface {
	Classify(ctx context.Context, objectID, fieldPath string, samples []string) (category, profile string, confidence float64, ok bool)
}

// Sampler supplies the bounded set of sample values a Scanner classifies for one field, drawn by
// whatever means the caller's database driver/catalog access provides (a read-only credential
// scan, e.g. the same shape as SKYBRIDGE_POSTGRES_CATALOG_DSN). Kept as a narrow interface, not a
// concrete type, since sampling strategy is entirely deployment/driver-specific and out of scope
// for this package.
type Sampler interface {
	// Sample returns up to maxSamples non-null values observed for fieldPath under objectID, and
	// ok=false if the field could not be sampled at all (e.g. an empty table, an unreachable
	// source) — never an error, since a sampling miss for one field must never abort a scan over
	// the rest of an object's fields.
	Sample(ctx context.Context, objectID, fieldPath string, maxSamples int) (samples []string, ok bool)
}

// Scanner drives Classifier over a set of (objectID, fieldPath) pairs supplied by the caller and
// writes every confident proposal into a label.Store as label.SourceProposed — never any other
// Source, so PathOverlay's confirm gate is untouched regardless of what Scan classifies. Zero value
// is not usable; call NewScanner.
type Scanner struct {
	classifier Classifier
	sampler    Sampler
	store      label.Store
	maxSamples int
}

// ScannerConfig configures a Scanner. All fields are required except MaxSamples.
type ScannerConfig struct {
	Classifier Classifier
	Sampler    Sampler
	Store      label.Store
	// MaxSamples bounds how many values are requested per field per scan. Default 20 — enough for
	// an LLM prompt or a small NER batch without pulling a large fraction of any real table, and
	// small enough that a sampling read never meaningfully competes with live query traffic for
	// the same read-only credential.
	MaxSamples int
}

const defaultMaxSamples = 20

// NewScanner returns a ready-to-use Scanner. Panics if cfg.Classifier, cfg.Sampler, or cfg.Store is
// nil — these are programmer errors (a missing dependency wired up wrong), not a runtime condition
// a caller should need to check for at every call site.
func NewScanner(cfg ScannerConfig) *Scanner {
	if cfg.Classifier == nil || cfg.Sampler == nil || cfg.Store == nil {
		panic("aiclassifier: NewScanner requires a non-nil Classifier, Sampler, and Store")
	}
	maxSamples := cfg.MaxSamples
	if maxSamples <= 0 {
		maxSamples = defaultMaxSamples
	}
	return &Scanner{classifier: cfg.Classifier, sampler: cfg.Sampler, store: cfg.Store, maxSamples: maxSamples}
}

// Field identifies one column/document field for ScanFields to classify.
type Field struct {
	ObjectID  string
	FieldPath string
}

// ScanFields samples and classifies every field in turn, proposing a label.Store entry for each
// confident result. A sampling miss, a classifier miss, or a Store.Put failure for one field is
// logged-equivalent (silently skipped) rather than aborting the scan — matching the "sync failure
// never blocks the rest of the scan" principle in docs/AI_PATH_LABELLING_DESIGN.md §5.5. Returns
// the count of fields a label was actually proposed for, primarily for caller-side observability
// (e.g. a scan-job log line), not for correctness — callers must not branch on it.
func (s *Scanner) ScanFields(ctx context.Context, fields []Field) int {
	proposed := 0
	for _, f := range fields {
		if s.scanOne(ctx, f) {
			proposed++
		}
	}
	return proposed
}

func (s *Scanner) scanOne(ctx context.Context, f Field) bool {
	if f.ObjectID == "" || f.FieldPath == "" {
		return false
	}
	samples, ok := s.sampler.Sample(ctx, f.ObjectID, f.FieldPath, s.maxSamples)
	if !ok || len(samples) == 0 {
		return false
	}
	category, profile, confidence, ok := s.classifier.Classify(ctx, f.ObjectID, f.FieldPath, samples)
	if !ok {
		return false
	}
	err := s.store.Put(ctx, label.Label{
		ObjectID:       f.ObjectID,
		FieldPath:      f.FieldPath,
		MatchMode:      label.MatchPath,
		Category:       category,
		Profile:        profile,
		Source:         label.SourceProposed,
		Confidence:     confidence,
		SampleCount:    len(samples),
		LastObservedAt: time.Now(),
	})
	return err == nil
}
