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
	c := []Column{{Name: "email", Path: "profile.contact.email", ObjectID: "org1:mongo:orders", Text: true}}
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
	c := []Column{{Name: "Email", ObjectID: "org1:postgres:users", Text: true}}
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
	c := []Column{{Name: "email", Text: true}} // no ObjectID: unresolved table/collection
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
	c := []Column{{Name: "email", ObjectID: "org1:mongo:orders", Text: true}}
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
	c := []Column{{Name: "internal_notes", ObjectID: "org1:postgres:orders", Text: true}}
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
	c := []Column{{Name: "email", ObjectID: "org1:x:y", Text: true}}
	out, err := p.MaskRow(context.Background(), c, [][]byte{[]byte("jane@example.com")})
	if err != nil {
		t.Fatal(err)
	}
	if string(out[0]) != "jane@example.com" {
		t.Fatal("nil store must be a no-op")
	}
}

var _ Masker = (*PathOverlay)(nil)
