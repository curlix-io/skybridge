//go:build querystudio

package dbquery

import (
	"context"
	"errors"
	"testing"

	"github.com/curlix-io/skybridge/internal/mask"
)

// pathSpyMasker records every mask.Column it was asked to mask and redacts nothing, so tests can
// assert exactly which (Name, Path, ObjectID) triples reached the masker.
type pathSpyMasker struct {
	seen []mask.Column
}

func (m *pathSpyMasker) MaskRow(_ context.Context, cols []mask.Column, row [][]byte) ([][]byte, error) {
	m.seen = append(m.seen, cols...)
	return row, nil
}

func TestMaskRows_PopulatesObjectIDAndPath(t *testing.T) {
	spy := &pathSpyMasker{}
	rows := []map[string]any{{"id": "1", "email": "a@b.com"}}
	_, err := maskRows(context.Background(), spy, "org1:postgres:app:app", []string{"id", "email"}, rows)
	if err != nil {
		t.Fatal(err)
	}
	if len(spy.seen) != 2 {
		t.Fatalf("expected 2 columns seen, got %d", len(spy.seen))
	}
	for _, c := range spy.seen {
		if c.ObjectID != "org1:postgres:app:app" {
			t.Fatalf("expected ObjectID propagated, got %q", c.ObjectID)
		}
		if c.Path != c.Name {
			t.Fatalf("expected Path == Name for tabular rows, got Path=%q Name=%q", c.Path, c.Name)
		}
	}
}

func TestMaskDocuments_ResolvesNestedPaths(t *testing.T) {
	spy := &pathSpyMasker{}
	docs := []map[string]any{
		{
			"order": map[string]any{"total": "100"},
			"user":  map[string]any{"total": "5"},
		},
	}
	_, err := maskDocuments(context.Background(), spy, "org1:mongo:app:orders", docs)
	if err != nil {
		t.Fatal(err)
	}
	paths := map[string]bool{}
	for _, c := range spy.seen {
		if c.ObjectID != "org1:mongo:app:orders" {
			t.Fatalf("expected ObjectID propagated, got %q", c.ObjectID)
		}
		paths[c.Path] = true
	}
	if !paths["order.total"] || !paths["user.total"] {
		t.Fatalf("expected independent paths order.total and user.total, got %+v", paths)
	}
}

func TestMaskDocuments_RedactsByPath(t *testing.T) {
	docs := []map[string]any{
		{"profile": map[string]any{"email": "jane@example.com", "name": "Jane"}},
	}
	stub := &redactPathMasker{redactPath: "profile.email"}
	out, err := maskDocuments(context.Background(), stub, "org1:mongo:app:users", docs)
	if err != nil {
		t.Fatal(err)
	}
	profile := out[0]["profile"].(map[string]any)
	if profile["email"] != "[redacted]" {
		t.Fatalf("expected email redacted, got %v", profile["email"])
	}
	if profile["name"] != "Jane" {
		t.Fatalf("expected name untouched, got %v", profile["name"])
	}
}

// redactPathMasker redacts only the column whose Path matches redactPath, leaving everything else
// unchanged — a minimal stand-in for PathOverlay to test maskDocuments' leaf/value re-assembly.
type redactPathMasker struct {
	redactPath string
}

func (m *redactPathMasker) MaskRow(_ context.Context, cols []mask.Column, row [][]byte) ([][]byte, error) {
	out := make([][]byte, len(row))
	for i, c := range cols {
		if c.Path == m.redactPath {
			out[i] = []byte("[redacted]")
		} else {
			out[i] = row[i]
		}
	}
	return out, nil
}

func TestMaskDocuments_NilMaskerIsNoop(t *testing.T) {
	docs := []map[string]any{{"email": "a@b.com"}}
	out, err := maskDocuments(context.Background(), nil, "org1:mongo:app:users", docs)
	if err != nil {
		t.Fatal(err)
	}
	if out[0]["email"] != "a@b.com" {
		t.Fatal("nil masker must not alter documents")
	}
}

// upperMasker uppercases ASCII letters in every non-nil value — used to assert a masker's output is
// actually applied to the row/document, independent of path-scoping behavior.
type upperMasker struct{}

func (upperMasker) MaskRow(_ context.Context, cols []mask.Column, row [][]byte) ([][]byte, error) {
	out := make([][]byte, len(row))
	for i, v := range row {
		if v == nil {
			continue
		}
		b := make([]byte, len(v))
		for j, c := range v {
			if c >= 'a' && c <= 'z' {
				c -= 'a' - 'A'
			}
			b[j] = c
		}
		out[i] = b
	}
	return out, nil
}

type errMasker struct{}

func (errMasker) MaskRow(context.Context, []mask.Column, [][]byte) ([][]byte, error) {
	return nil, errors.New("mask failed")
}

func TestMaskRowsNilMaskerPassesThrough(t *testing.T) {
	rows := []map[string]any{{"name": "alice"}}
	out, err := maskRows(context.Background(), nil, "", []string{"name"}, rows)
	if err != nil {
		t.Fatal(err)
	}
	if out[0]["name"] != "alice" {
		t.Fatalf("expected rows unchanged, got %v", out)
	}
}

func TestMaskRowsAppliesMasker(t *testing.T) {
	rows := []map[string]any{{"name": "alice", "age": nil}}
	out, err := maskRows(context.Background(), upperMasker{}, "", []string{"name", "age"}, rows)
	if err != nil {
		t.Fatal(err)
	}
	if out[0]["name"] != "ALICE" {
		t.Fatalf("expected masked value, got %v", out[0]["name"])
	}
	if out[0]["age"] != nil {
		t.Fatalf("expected nil preserved, got %v", out[0]["age"])
	}
}

func TestMaskRowsPropagatesMaskerError(t *testing.T) {
	rows := []map[string]any{{"name": "alice"}}
	_, err := maskRows(context.Background(), errMasker{}, "", []string{"name"}, rows)
	if err == nil {
		t.Fatal("expected masker error to propagate")
	}
}

func TestMaskDocumentsNilMaskerPassesThrough(t *testing.T) {
	docs := []map[string]any{{"email": "a@b.com"}}
	out, err := maskDocuments(context.Background(), nil, "", docs)
	if err != nil {
		t.Fatal(err)
	}
	if out[0]["email"] != "a@b.com" {
		t.Fatalf("expected docs unchanged, got %v", out)
	}
}

func TestMaskDocumentsAppliesMaskerWithStableColumnOrder(t *testing.T) {
	docs := []map[string]any{{"b": "second", "a": "first", "c": nil}}
	out, err := maskDocuments(context.Background(), upperMasker{}, "", docs)
	if err != nil {
		t.Fatal(err)
	}
	if out[0]["a"] != "FIRST" || out[0]["b"] != "SECOND" {
		t.Fatalf("expected masked doc, got %v", out[0])
	}
	if out[0]["c"] != nil {
		t.Fatalf("expected nil field preserved, got %v", out[0]["c"])
	}
}

func TestMaskDocumentsPropagatesMaskerError(t *testing.T) {
	docs := []map[string]any{{"a": "1"}}
	_, err := maskDocuments(context.Background(), errMasker{}, "", docs)
	if err == nil {
		t.Fatal("expected masker error to propagate")
	}
}
