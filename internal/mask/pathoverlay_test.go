package mask

import (
	"context"
	"testing"

	"github.com/curlix-io/skybridge/internal/pathlabel/label"
)

func TestPathOverlay_MatchesByPath(t *testing.T) {
	store := label.NewMemStore()
	ctx := context.Background()
	if err := store.Put(ctx, label.Label{
		ObjectID:  "org1:mongo:orders",
		FieldPath: "profile.contact.email",
		MatchMode: label.MatchPath,
		Category:  "email_fields",
		Profile:   "full_redact",
		Source:    label.SourceManual,
	}); err != nil {
		t.Fatal(err)
	}

	p := NewPathOverlay(store)
	c := []Column{{Name: "email", Path: "profile.contact.email", ObjectID: "org1:mongo:orders", Text: true, FreeText: true}}
	out, err := p.MaskRow(ctx, c, [][]byte{[]byte("jane@example.com")})
	if err != nil {
		t.Fatal(err)
	}
	if string(out[0]) != "[redacted]" {
		t.Fatalf("expected path-scoped redaction, got %q", out[0])
	}
}

func TestPathOverlay_FallsBackToBareKey(t *testing.T) {
	store := label.NewMemStore()
	ctx := context.Background()
	if err := store.Put(ctx, label.Label{
		ObjectID:  "org1:postgres:users",
		FieldPath: "email",
		MatchMode: label.MatchKeyAnyDepth,
		Category:  "email_fields",
		Profile:   "full_redact",
		Source:    label.SourceManual,
	}); err != nil {
		t.Fatal(err)
	}

	p := NewPathOverlay(store)
	// No Path set (tabular row) and no exact path label exists — falls back to the bare column name.
	c := []Column{{Name: "Email", ObjectID: "org1:postgres:users", Text: true, FreeText: true}}
	out, err := p.MaskRow(ctx, c, [][]byte{[]byte("jane@example.com")})
	if err != nil {
		t.Fatal(err)
	}
	if string(out[0]) != "[redacted]" {
		t.Fatalf("expected bare-key fallback redaction, got %q", out[0])
	}
}

func TestPathOverlay_EmptyObjectIDIsNoop(t *testing.T) {
	store := label.NewMemStore()
	_ = store.Put(context.Background(), label.Label{
		ObjectID: "org1:postgres:users", FieldPath: "email", Source: label.SourceManual, Profile: "full_redact",
	})
	p := NewPathOverlay(store)
	c := []Column{{Name: "email", Text: true, FreeText: true}} // no ObjectID: unresolved table/collection
	out, err := p.MaskRow(context.Background(), c, [][]byte{[]byte("jane@example.com")})
	if err != nil {
		t.Fatal(err)
	}
	if string(out[0]) != "jane@example.com" {
		t.Fatal("empty ObjectID must not match any label")
	}
}

func TestPathOverlay_ProposedLabelIsInert(t *testing.T) {
	store := label.NewMemStore()
	ctx := context.Background()
	_ = store.Put(ctx, label.Label{
		ObjectID: "org1:mongo:orders", FieldPath: "email", Source: label.SourceProposed,
		Category: "email_fields", Profile: "full_redact", Confidence: 0.95,
	})
	p := NewPathOverlay(store)
	c := []Column{{Name: "email", ObjectID: "org1:mongo:orders", Text: true, FreeText: true}}
	out, err := p.MaskRow(ctx, c, [][]byte{[]byte("jane@example.com")})
	if err != nil {
		t.Fatal(err)
	}
	if string(out[0]) != "jane@example.com" {
		t.Fatal("a SourceProposed label must never redact live")
	}
}

func TestPathOverlay_DoNotMask(t *testing.T) {
	store := label.NewMemStore()
	ctx := context.Background()
	_ = store.Put(ctx, label.Label{
		ObjectID: "org1:postgres:orders", FieldPath: "internal_notes", Source: label.SourceManual, Profile: "do_not_mask",
	})
	p := NewPathOverlay(store)
	c := []Column{{Name: "internal_notes", ObjectID: "org1:postgres:orders", Text: true, FreeText: true}}
	out, err := p.MaskRow(ctx, c, [][]byte{[]byte("plain text")})
	if err != nil {
		t.Fatal(err)
	}
	if string(out[0]) != "plain text" {
		t.Fatalf("do_not_mask label must pass the value through, got %q", out[0])
	}
}

func TestPathOverlay_NilStoreIsNoop(t *testing.T) {
	p := NewPathOverlay(nil)
	c := []Column{{Name: "email", ObjectID: "org1:x:y", Text: true, FreeText: true}}
	out, err := p.MaskRow(context.Background(), c, [][]byte{[]byte("jane@example.com")})
	if err != nil {
		t.Fatal(err)
	}
	if string(out[0]) != "jane@example.com" {
		t.Fatal("nil store must be a no-op")
	}
}

// seedSpyStore wraps a MemStore and records every ObjectID passed to SeedObject, so tests can
// assert PathOverlay seeds a sync-backed Store on lookup without needing the real remotestore.
type seedSpyStore struct {
	*label.MemStore
	seeded []string
}

func (s *seedSpyStore) SeedObject(objectID string) {
	s.seeded = append(s.seeded, objectID)
}

func TestPathOverlay_SeedsStoreOnLookup(t *testing.T) {
	store := &seedSpyStore{MemStore: label.NewMemStore()}
	p := NewPathOverlay(store)
	c := []Column{{Name: "email", ObjectID: "org1:mongo:orders", Text: true, FreeText: true}}
	if _, err := p.MaskRow(context.Background(), c, [][]byte{[]byte("jane@example.com")}); err != nil {
		t.Fatal(err)
	}
	if len(store.seeded) != 1 || store.seeded[0] != "org1:mongo:orders" {
		t.Fatalf("expected SeedObject called once with org1:mongo:orders, got %+v", store.seeded)
	}
}

func TestPathOverlay_NonSeederStoreIsUnaffected(t *testing.T) {
	// label.MemStore does not implement seeder — MaskRow must not panic or behave differently.
	store := label.NewMemStore()
	p := NewPathOverlay(store)
	c := []Column{{Name: "email", ObjectID: "org1:mongo:orders", Text: true, FreeText: true}}
	if _, err := p.MaskRow(context.Background(), c, [][]byte{[]byte("jane@example.com")}); err != nil {
		t.Fatal(err)
	}
}

func TestPathOverlay_RecordsAnalyzedAndMaskedOnRedact(t *testing.T) {
	store := label.NewMemStore()
	ctx := context.Background()
	_ = store.Put(ctx, label.Label{
		ObjectID: "org1:postgres:orders", FieldPath: "email", Source: label.SourceManual,
		Category: "email_fields", Profile: "full_redact",
	})
	fake := &fakeMetricsRecorder{}
	p := NewPathOverlayWithMetrics(store, fake, "postgres__primary")
	c := []Column{{Name: "email", ObjectID: "org1:postgres:orders", Text: true, FreeText: true}}
	out, err := p.MaskRow(ctx, c, [][]byte{[]byte("jane@example.com")})
	if err != nil {
		t.Fatal(err)
	}
	if string(out[0]) != "[redacted]" {
		t.Fatalf("expected redaction, got %q", out[0])
	}
	if len(fake.analyzed) != 1 || fake.analyzed[0] != "postgres__primary|field_rule" {
		t.Fatalf("expected one RecordAnalyzed call, got %+v", fake.analyzed)
	}
	if len(fake.masked) != 1 || fake.masked[0].entityType != "email_fields" || fake.masked[0].source != "field_rule" || fake.masked[0].byteCount != len("jane@example.com") {
		t.Fatalf("expected one RecordMasked call for email_fields/field_rule, got %+v", fake.masked)
	}
}

func TestPathOverlay_RecordsAnalyzedOnlyForDoNotMask(t *testing.T) {
	store := label.NewMemStore()
	ctx := context.Background()
	_ = store.Put(ctx, label.Label{
		ObjectID: "org1:postgres:orders", FieldPath: "internal_notes", Source: label.SourceManual, Profile: "do_not_mask",
		Category: "internal_notes_category",
	})
	fake := &fakeMetricsRecorder{}
	p := NewPathOverlayWithMetrics(store, fake, "postgres__primary")
	c := []Column{{Name: "internal_notes", ObjectID: "org1:postgres:orders", Text: true, FreeText: true}}
	out, err := p.MaskRow(ctx, c, [][]byte{[]byte("plain text")})
	if err != nil {
		t.Fatal(err)
	}
	if string(out[0]) != "plain text" {
		t.Fatalf("do_not_mask label must pass the value through, got %q", out[0])
	}
	if len(fake.analyzed) != 1 {
		t.Fatalf("expected RecordAnalyzed called once even for do_not_mask (analyzed, not masked), got %+v", fake.analyzed)
	}
	if len(fake.masked) != 0 {
		t.Fatalf("expected no RecordMasked calls for do_not_mask, got %+v", fake.masked)
	}
}

func TestPathOverlay_NoAnalyzedRecordedWhenObjectIDEmpty(t *testing.T) {
	store := label.NewMemStore()
	fake := &fakeMetricsRecorder{}
	p := NewPathOverlayWithMetrics(store, fake, "postgres__primary")
	c := []Column{{Name: "email", Text: true, FreeText: true}} // no ObjectID
	if _, err := p.MaskRow(context.Background(), c, [][]byte{[]byte("jane@example.com")}); err != nil {
		t.Fatal(err)
	}
	if len(fake.analyzed) != 0 || len(fake.masked) != 0 {
		t.Fatalf("expected no metrics recorded when ObjectID is empty (no lookup attempted), got analyzed=%+v masked=%+v", fake.analyzed, fake.masked)
	}
}

func TestPathOverlay_NilMetricsIsNoop(t *testing.T) {
	store := label.NewMemStore()
	_ = store.Put(context.Background(), label.Label{
		ObjectID: "org1:postgres:orders", FieldPath: "email", Source: label.SourceManual, Profile: "full_redact",
	})
	p := NewPathOverlay(store)
	c := []Column{{Name: "email", ObjectID: "org1:postgres:orders", Text: true, FreeText: true}}
	out, err := p.MaskRow(context.Background(), c, [][]byte{[]byte("jane@example.com")})
	if err != nil {
		t.Fatal(err)
	}
	if string(out[0]) != "[redacted]" {
		t.Fatalf("expected redaction to still work with nil metrics, got %q", out[0])
	}
}

var _ Masker = (*PathOverlay)(nil)
