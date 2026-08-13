package trafficsampler

import (
	"context"
	"testing"
	"time"

	"github.com/curlix-io/skybridge/internal/pathlabel/aiclassifier"
	"github.com/curlix-io/skybridge/internal/pathlabel/label"
)

type fakeClassifier struct {
	calls int
}

func (f *fakeClassifier) Classify(_ context.Context, _, _ string, samples []string) (string, string, float64, bool) {
	f.calls++
	if len(samples) == 0 {
		return "", "", 0, false
	}
	return "email", "contact", 0.9, true
}

func TestRun_ScansBufferedFieldsUntilContextDone(t *testing.T) {
	buf := New(10, 5)
	buf.Observe("org1:postgres:app:users", "email", "a@example.com")

	store := label.NewMemStore()
	classifier := &fakeClassifier{}
	scanner := aiclassifier.NewScanner(aiclassifier.ScannerConfig{
		Classifier: classifier,
		Sampler:    buf,
		Store:      store,
	})

	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()
	Run(ctx, RunnerConfig{Buffer: buf, Scanner: scanner, ScanIntervalSeconds: 1000}, nil)

	l, ok, err := store.Lookup(context.Background(), "org1:postgres:app:users", "email")
	if err != nil {
		t.Fatal(err)
	}
	if !ok {
		t.Fatal("expected a proposed label from the initial scan")
	}
	if l.Source != label.SourceProposed || l.Category != "email" {
		t.Fatalf("unexpected proposed label: %+v", l)
	}
	if classifier.calls == 0 {
		t.Fatal("expected Classify to be called at least once")
	}
}

func TestRun_SkipsScanWhenBufferEmpty(t *testing.T) {
	buf := New(10, 5)
	classifier := &fakeClassifier{}
	scanner := aiclassifier.NewScanner(aiclassifier.ScannerConfig{
		Classifier: classifier,
		Sampler:    buf,
		Store:      label.NewMemStore(),
	})

	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel()
	Run(ctx, RunnerConfig{Buffer: buf, Scanner: scanner, ScanIntervalSeconds: 1000}, nil)

	if classifier.calls != 0 {
		t.Fatalf("expected no Classify calls against an empty buffer, got %d", classifier.calls)
	}
}
