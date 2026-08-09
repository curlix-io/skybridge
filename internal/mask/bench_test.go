package mask

import (
	"context"
	"testing"

	"github.com/curlix-io/skybridge/internal/pathlabel/label"
)

// benchRow builds a fixed 5-column row: an id, two free-text columns eligible for masking, and two
// typed (non-free-text) columns that every layer must skip untouched — representative of a typical
// SELECT rather than an all-PII worst case.
func benchRow() ([]Column, [][]byte) {
	cols := []Column{
		{Name: "id", Text: true, FreeText: false},
		{Name: "email", Text: true, FreeText: true, Path: "email"},
		{Name: "notes", Text: true, FreeText: true, Path: "notes"},
		{Name: "created_at", Text: true, FreeText: false},
		{Name: "amount_cents", Text: true, FreeText: false},
	}
	row := [][]byte{
		[]byte("42"),
		[]byte("jane.doe@example.com"),
		[]byte("called about renewal, mentioned husband John Doe, SSN 123-45-6789"),
		[]byte("2026-01-15T00:00:00Z"),
		[]byte("19999"),
	}
	return cols, row
}

func BenchmarkOverlay_MaskRow(b *testing.B) {
	o := NewOverlay(map[string]string{"email": "[redacted]"})
	cols, row := benchRow()
	ctx := context.Background()
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		fresh := append([][]byte(nil), row...)
		if _, err := o.MaskRow(ctx, cols, fresh); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkPathOverlay_MaskRow_Hit(b *testing.B) {
	store := label.NewMemStore()
	ctx := context.Background()
	if err := store.Put(ctx, label.Label{
		ObjectID:  "org1:pg:public.customers",
		FieldPath: "email",
		MatchMode: label.MatchPath,
		Profile:   "full_redact",
		Source:    label.SourceManual,
	}); err != nil {
		b.Fatal(err)
	}
	p := NewPathOverlay(store)
	cols, row := benchRow()
	for i := range cols {
		cols[i].ObjectID = "org1:pg:public.customers"
	}
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		fresh := append([][]byte(nil), row...)
		if _, err := p.MaskRow(ctx, cols, fresh); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkPathOverlay_MaskRow_Miss(b *testing.B) {
	store := label.NewMemStore()
	p := NewPathOverlay(store)
	cols, row := benchRow()
	ctx := context.Background()
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		fresh := append([][]byte(nil), row...)
		if _, err := p.MaskRow(ctx, cols, fresh); err != nil {
			b.Fatal(err)
		}
	}
}

// BenchmarkChain_OverlayOnly approximates the default OSS deployment (no remote masker configured):
// PathOverlay (unconfigured, mask.Noop equivalent via nil store) + Overlay only.
func BenchmarkChain_OverlayOnly(b *testing.B) {
	o := NewOverlay(map[string]string{"email": "[redacted]"})
	chain := NewChain(o)
	cols, row := benchRow()
	ctx := context.Background()
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		fresh := append([][]byte(nil), row...)
		if _, err := chain.MaskRow(ctx, cols, fresh); err != nil {
			b.Fatal(err)
		}
	}
}

// BenchmarkChain_PathOverlayAndOverlay approximates a deployment with path-scoped labels
// (SKYBRIDGE_PATH_LABEL_URL) layered on top of the static column overlay, no remote masker.
func BenchmarkChain_PathOverlayAndOverlay(b *testing.B) {
	store := label.NewMemStore()
	ctx := context.Background()
	if err := store.Put(ctx, label.Label{
		ObjectID:  "org1:pg:public.customers",
		FieldPath: "email",
		MatchMode: label.MatchPath,
		Profile:   "full_redact",
		Source:    label.SourceManual,
	}); err != nil {
		b.Fatal(err)
	}
	p := NewPathOverlay(store)
	o := NewOverlay(map[string]string{"notes": "[redacted]"})
	chain := NewChain(p, o)
	cols, row := benchRow()
	for i := range cols {
		cols[i].ObjectID = "org1:pg:public.customers"
	}
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		fresh := append([][]byte(nil), row...)
		if _, err := chain.MaskRow(ctx, cols, fresh); err != nil {
			b.Fatal(err)
		}
	}
}
