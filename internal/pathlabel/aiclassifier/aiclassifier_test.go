package aiclassifier

import (
	"context"
	"errors"
	"testing"

	"github.com/curlix-io/skybridge/internal/pathlabel/label"
)

type fakeSampler struct {
	samples map[string][]string
}

func (f *fakeSampler) Sample(_ context.Context, objectID, fieldPath string, maxSamples int) ([]string, bool) {
	s, ok := f.samples[objectID+"|"+fieldPath]
	if !ok {
		return nil, false
	}
	if len(s) > maxSamples {
		s = s[:maxSamples]
	}
	return s, true
}

type fakeClassifier struct {
	category, profile string
	confidence        float64
	ok                bool
	calls             int
}

func (f *fakeClassifier) Classify(_ context.Context, _, _ string, _ []string) (string, string, float64, bool) {
	f.calls++
	return f.category, f.profile, f.confidence, f.ok
}

type errStore struct{ err error }

func (e *errStore) Lookup(context.Context, string, string) (label.Label, bool, error) {
	return label.Label{}, false, nil
}
func (e *errStore) Put(context.Context, label.Label) error { return e.err }
func (e *errStore) ListBySource(context.Context, string, label.Source) ([]label.Label, error) {
	return nil, nil
}

func TestNewScanner_PanicsOnMissingDependency(t *testing.T) {
	defer func() {
		if recover() == nil {
			t.Fatal("expected panic when a required dependency is nil")
		}
	}()
	NewScanner(ScannerConfig{Sampler: &fakeSampler{}, Store: label.NewMemStore()})
}

func TestScanFields_ProposesConfidentClassification(t *testing.T) {
	store := label.NewMemStore()
	sampler := &fakeSampler{samples: map[string][]string{
		"org:pg:db:users|email": {"alice@example.com", "bob@example.com"},
	}}
	classifier := &fakeClassifier{category: "email_fields", profile: "full_redact", confidence: 0.9, ok: true}
	s := NewScanner(ScannerConfig{Classifier: classifier, Sampler: sampler, Store: store})

	n := s.ScanFields(context.Background(), []Field{{ObjectID: "org:pg:db:users", FieldPath: "email"}})
	if n != 1 {
		t.Fatalf("expected 1 field proposed, got %d", n)
	}

	got, ok, err := store.Lookup(context.Background(), "org:pg:db:users", "email")
	if err != nil || !ok {
		t.Fatalf("expected a proposed label, err=%v ok=%v", err, ok)
	}
	if got.Source != label.SourceProposed {
		t.Fatalf("expected Source=proposed, got %q", got.Source)
	}
	if got.Category != "email_fields" || got.Profile != "full_redact" || got.Confidence != 0.9 {
		t.Fatalf("unexpected label: %+v", got)
	}
	if got.SampleCount != 2 {
		t.Fatalf("expected SampleCount=2, got %d", got.SampleCount)
	}
}

func TestScanFields_SkipsWhenSamplerMisses(t *testing.T) {
	store := label.NewMemStore()
	classifier := &fakeClassifier{ok: true, category: "x"}
	s := NewScanner(ScannerConfig{Classifier: classifier, Sampler: &fakeSampler{samples: map[string][]string{}}, Store: store})

	n := s.ScanFields(context.Background(), []Field{{ObjectID: "org:pg:db:t", FieldPath: "col"}})
	if n != 0 {
		t.Fatalf("expected 0 proposed on sampler miss, got %d", n)
	}
	if classifier.calls != 0 {
		t.Fatalf("expected Classify never called on sampler miss, got %d calls", classifier.calls)
	}
}

func TestScanFields_SkipsWhenClassifierDeclinesToPropose(t *testing.T) {
	store := label.NewMemStore()
	sampler := &fakeSampler{samples: map[string][]string{"org:pg:db:t|col": {"v1"}}}
	classifier := &fakeClassifier{ok: false}
	s := NewScanner(ScannerConfig{Classifier: classifier, Sampler: sampler, Store: store})

	n := s.ScanFields(context.Background(), []Field{{ObjectID: "org:pg:db:t", FieldPath: "col"}})
	if n != 0 {
		t.Fatalf("expected 0 proposed when classifier returns ok=false, got %d", n)
	}
}

func TestScanFields_ContinuesPastOneFieldsStoreFailure(t *testing.T) {
	sampler := &fakeSampler{samples: map[string][]string{
		"org|a": {"v1"},
		"org|b": {"v2"},
	}}
	classifier := &fakeClassifier{category: "x", confidence: 0.5, ok: true}
	s := NewScanner(ScannerConfig{Classifier: classifier, Sampler: sampler, Store: &errStore{err: errors.New("boom")}})

	n := s.ScanFields(context.Background(), []Field{
		{ObjectID: "org", FieldPath: "a"},
		{ObjectID: "org", FieldPath: "b"},
	})
	if n != 0 {
		t.Fatalf("expected 0 successful proposals when every Put fails, got %d", n)
	}
	if classifier.calls != 2 {
		t.Fatalf("expected both fields still classified despite Store.Put failing, got %d calls", classifier.calls)
	}
}

func TestScanFields_SkipsEmptyIdentity(t *testing.T) {
	store := label.NewMemStore()
	classifier := &fakeClassifier{ok: true, category: "x"}
	s := NewScanner(ScannerConfig{Classifier: classifier, Sampler: &fakeSampler{samples: map[string][]string{}}, Store: store})

	n := s.ScanFields(context.Background(), []Field{{ObjectID: "", FieldPath: "col"}, {ObjectID: "org", FieldPath: ""}})
	if n != 0 {
		t.Fatalf("expected 0 proposed for fields with empty ObjectID/FieldPath, got %d", n)
	}
}

func TestScanFields_RespectsMaxSamplesCap(t *testing.T) {
	store := label.NewMemStore()
	sampler := &fakeSampler{samples: map[string][]string{"org|col": {"a", "b", "c", "d", "e"}}}
	classifier := &fakeClassifier{category: "x", confidence: 0.5, ok: true}
	s := NewScanner(ScannerConfig{Classifier: classifier, Sampler: sampler, Store: store, MaxSamples: 2})

	s.ScanFields(context.Background(), []Field{{ObjectID: "org", FieldPath: "col"}})

	got, _, _ := store.Lookup(context.Background(), "org", "col")
	if got.SampleCount != 2 {
		t.Fatalf("expected SampleCount capped at MaxSamples=2, got %d", got.SampleCount)
	}
}
