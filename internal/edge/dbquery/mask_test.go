package dbquery

import (
	"context"
	"errors"
	"testing"

	"github.com/curlix-io/skybridge/internal/mask"
)

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
	out, err := maskRows(context.Background(), nil, []string{"name"}, rows)
	if err != nil {
		t.Fatal(err)
	}
	if out[0]["name"] != "alice" {
		t.Fatalf("expected rows unchanged, got %v", out)
	}
}

func TestMaskRowsAppliesMasker(t *testing.T) {
	rows := []map[string]any{{"name": "alice", "age": nil}}
	out, err := maskRows(context.Background(), upperMasker{}, []string{"name", "age"}, rows)
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
	_, err := maskRows(context.Background(), errMasker{}, []string{"name"}, rows)
	if err == nil {
		t.Fatal("expected masker error to propagate")
	}
}

func TestMaskDocumentsNilMaskerPassesThrough(t *testing.T) {
	docs := []map[string]any{{"email": "a@b.com"}}
	out, err := maskDocuments(context.Background(), nil, docs)
	if err != nil {
		t.Fatal(err)
	}
	if out[0]["email"] != "a@b.com" {
		t.Fatalf("expected docs unchanged, got %v", out)
	}
}

func TestMaskDocumentsAppliesMaskerWithStableColumnOrder(t *testing.T) {
	docs := []map[string]any{{"b": "second", "a": "first", "c": nil}}
	out, err := maskDocuments(context.Background(), upperMasker{}, docs)
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
	_, err := maskDocuments(context.Background(), errMasker{}, docs)
	if err == nil {
		t.Fatal("expected masker error to propagate")
	}
}
