package trafficsampler

import (
	"context"
	"testing"
)

func TestBuffer_ObserveAndSample(t *testing.T) {
	b := New(10, 5)
	b.Observe("org1:postgres:app:users", "email", "a@example.com")
	b.Observe("org1:postgres:app:users", "email", "b@example.com")

	samples, ok := b.Sample(context.Background(), "org1:postgres:app:users", "email", 10)
	if !ok {
		t.Fatal("expected samples for an observed field")
	}
	if len(samples) != 2 || samples[0] != "a@example.com" || samples[1] != "b@example.com" {
		t.Fatalf("unexpected samples: %v", samples)
	}
}

func TestBuffer_SampleMissReturnsFalse(t *testing.T) {
	b := New(10, 5)
	if _, ok := b.Sample(context.Background(), "org1:postgres:app:users", "email", 10); ok {
		t.Fatal("expected ok=false for a field with no observations")
	}
}

func TestBuffer_ObserveDropsBlankInputs(t *testing.T) {
	b := New(10, 5)
	b.Observe("", "email", "a@example.com")
	b.Observe("org1:postgres:app:users", "", "a@example.com")
	b.Observe("org1:postgres:app:users", "email", "")
	if len(b.Fields()) != 0 {
		t.Fatalf("expected no fields buffered, got %v", b.Fields())
	}
}

func TestBuffer_MaxSamplesPerFieldCaps(t *testing.T) {
	b := New(10, 2)
	b.Observe("obj", "field", "1")
	b.Observe("obj", "field", "2")
	b.Observe("obj", "field", "3")

	samples, ok := b.Sample(context.Background(), "obj", "field", 10)
	if !ok {
		t.Fatal("expected samples")
	}
	if len(samples) != 2 || samples[0] != "1" || samples[1] != "2" {
		t.Fatalf("expected the buffer to keep only the first 2 observed values, got %v", samples)
	}
}

func TestBuffer_SampleRespectsMaxSamplesArg(t *testing.T) {
	b := New(10, 10)
	for _, v := range []string{"1", "2", "3", "4"} {
		b.Observe("obj", "field", v)
	}
	samples, ok := b.Sample(context.Background(), "obj", "field", 2)
	if !ok || len(samples) != 2 {
		t.Fatalf("expected 2 samples, got %v (ok=%v)", samples, ok)
	}
}

func TestBuffer_EvictsLeastRecentlyObservedFieldWhenFull(t *testing.T) {
	b := New(2, 5)
	b.Observe("obj1", "field", "a")
	b.Observe("obj2", "field", "b")
	// Touch obj1 again so obj2 becomes the least-recently-observed field.
	b.Observe("obj1", "field", "a2")
	b.Observe("obj3", "field", "c")

	if _, ok := b.Sample(context.Background(), "obj2", "field", 10); ok {
		t.Fatal("expected obj2's field to have been evicted as least-recently-observed")
	}
	if _, ok := b.Sample(context.Background(), "obj1", "field", 10); !ok {
		t.Fatal("expected obj1's field to survive since it was re-observed")
	}
	if _, ok := b.Sample(context.Background(), "obj3", "field", 10); !ok {
		t.Fatal("expected obj3's field to be present as the most recent addition")
	}
}

func TestBuffer_Fields(t *testing.T) {
	b := New(10, 5)
	b.Observe("org1:postgres:app:users", "email", "a@example.com")
	b.Observe("org1:postgres:app:orders", "total", "100")

	fields := b.Fields()
	if len(fields) != 2 {
		t.Fatalf("expected 2 fields, got %v", fields)
	}
	seen := map[string]bool{}
	for _, f := range fields {
		seen[f.ObjectID+"|"+f.FieldPath] = true
	}
	if !seen["org1:postgres:app:users|email"] || !seen["org1:postgres:app:orders|total"] {
		t.Fatalf("missing expected fields: %v", fields)
	}
}

func TestNew_DefaultsAppliedForNonPositiveArgs(t *testing.T) {
	b := New(0, 0)
	if b.maxFields <= 0 || b.maxSamples <= 0 {
		t.Fatalf("expected positive defaults, got maxFields=%d maxSamples=%d", b.maxFields, b.maxSamples)
	}
}
