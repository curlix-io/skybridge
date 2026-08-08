package label

import (
	"context"
	"testing"
	"time"
)

func TestMemStore_PutLookup(t *testing.T) {
	s := NewMemStore()
	ctx := context.Background()

	l := Label{
		ObjectID:  "tenant1:mongo:orders",
		FieldPath: "profile.contact.email",
		MatchMode: MatchPath,
		Category:  "email_fields",
		Profile:   "full_redact",
		Source:    SourceManual,
	}
	if err := s.Put(ctx, l); err != nil {
		t.Fatalf("Put: %v", err)
	}

	got, ok, err := s.Lookup(ctx, "tenant1:mongo:orders", "profile.contact.email")
	if err != nil {
		t.Fatalf("Lookup: %v", err)
	}
	if !ok {
		t.Fatalf("expected a hit")
	}
	if got.Category != "email_fields" {
		t.Fatalf("got category %q", got.Category)
	}

	if _, ok, _ := s.Lookup(ctx, "tenant1:mongo:orders", "profile.contact.phone"); ok {
		t.Fatalf("expected a miss for an unlabelled path")
	}
}

func TestMemStore_Put_RequiresKeys(t *testing.T) {
	s := NewMemStore()
	if err := s.Put(context.Background(), Label{}); err == nil {
		t.Fatalf("expected error for empty ObjectID/FieldPath")
	}
}

func TestMemStore_Put_ManualIsLastWriteWins(t *testing.T) {
	s := NewMemStore()
	ctx := context.Background()

	first := Label{ObjectID: "obj", FieldPath: "p", Source: SourceManual, Category: "a"}
	second := Label{ObjectID: "obj", FieldPath: "p", Source: SourceManual, Category: "b"}

	_ = s.Put(ctx, first)
	_ = s.Put(ctx, second)

	got, _, _ := s.Lookup(ctx, "obj", "p")
	if got.Category != "b" {
		t.Fatalf("expected last-write-wins, got category %q", got.Category)
	}
}

func TestMemStore_Put_ProposedMergesSampleCountAndMaxConfidence(t *testing.T) {
	s := NewMemStore()
	ctx := context.Background()

	t1 := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	t2 := t1.Add(time.Hour)

	first := Label{
		ObjectID: "obj", FieldPath: "p", Source: SourceProposed,
		Confidence: 0.6, SampleCount: 3, LastObservedAt: t1, UpdatedAt: t1,
	}
	second := Label{
		ObjectID: "obj", FieldPath: "p", Source: SourceProposed,
		Confidence: 0.4, SampleCount: 2, LastObservedAt: t2, UpdatedAt: t2,
	}

	if err := s.Put(ctx, first); err != nil {
		t.Fatalf("Put first: %v", err)
	}
	if err := s.Put(ctx, second); err != nil {
		t.Fatalf("Put second: %v", err)
	}

	got, ok, _ := s.Lookup(ctx, "obj", "p")
	if !ok {
		t.Fatalf("expected a hit")
	}
	if got.SampleCount != 5 {
		t.Fatalf("expected accumulated SampleCount 5, got %d", got.SampleCount)
	}
	if got.Confidence != 0.6 {
		t.Fatalf("expected max confidence 0.6, got %v", got.Confidence)
	}
	if !got.LastObservedAt.Equal(t2) {
		t.Fatalf("expected later LastObservedAt %v, got %v", t2, got.LastObservedAt)
	}
}

func TestMemStore_Put_ManualOverwritesProposed_NoMerge(t *testing.T) {
	s := NewMemStore()
	ctx := context.Background()

	proposed := Label{ObjectID: "obj", FieldPath: "p", Source: SourceProposed, Confidence: 0.9, SampleCount: 10}
	_ = s.Put(ctx, proposed)

	confirmed := Label{ObjectID: "obj", FieldPath: "p", Source: SourceManual, Category: "email_fields"}
	if err := s.Put(ctx, confirmed); err != nil {
		t.Fatalf("Put: %v", err)
	}

	got, _, _ := s.Lookup(ctx, "obj", "p")
	if got.Source != SourceManual || got.Category != "email_fields" {
		t.Fatalf("expected confirmed manual label to win outright, got %+v", got)
	}
	if got.SampleCount == 10 {
		t.Fatalf("manual confirm should not inherit proposed SampleCount via merge")
	}
}

func TestMemStore_ListBySource(t *testing.T) {
	s := NewMemStore()
	ctx := context.Background()

	_ = s.Put(ctx, Label{ObjectID: "obj", FieldPath: "a", Source: SourceProposed})
	_ = s.Put(ctx, Label{ObjectID: "obj", FieldPath: "b", Source: SourceProposed})
	_ = s.Put(ctx, Label{ObjectID: "obj", FieldPath: "c", Source: SourceManual})
	_ = s.Put(ctx, Label{ObjectID: "other", FieldPath: "a", Source: SourceProposed})

	proposed, err := s.ListBySource(ctx, "obj", SourceProposed)
	if err != nil {
		t.Fatalf("ListBySource: %v", err)
	}
	if len(proposed) != 2 {
		t.Fatalf("expected 2 proposed labels for obj, got %d (%+v)", len(proposed), proposed)
	}
}

var _ Store = (*MemStore)(nil)
