package dbquery

import (
	"context"
	"testing"

	"github.com/curlix-io/skybridge/internal/mask"
	"github.com/curlix-io/skybridge/internal/pathlabel/label"
)

// wrongCountMasker returns fewer values than it was given — used to exercise maskDocuments' own
// length-mismatch guard (distinct from mask.Chain's internal invariant, this is dbquery's own
// defensive check before it indexes into the returned slice).
type wrongCountMasker struct{}

func (wrongCountMasker) MaskRow(_ context.Context, cols []mask.Column, _ [][]byte) ([][]byte, error) {
	if len(cols) == 0 {
		return nil, nil
	}
	return make([][]byte, len(cols)-1), nil
}

// TestMaskDocuments_ErrorsOnMaskerLengthMismatch exercises maskDocuments' defensive
// len(masked) != len(raw) guard, which protects the position-counter-based Replace below it from
// indexing past the end of a short masker response.
func TestMaskDocuments_ErrorsOnMaskerLengthMismatch(t *testing.T) {
	docs := []map[string]any{{"a": "1", "b": "2"}}
	_, err := maskDocuments(context.Background(), wrongCountMasker{}, nil, nil, "", docs)
	if err == nil {
		t.Fatal("expected an error when the masker returns the wrong number of values")
	}
}

// nilifyMasker returns nil for every value — used to exercise maskDocuments' "masked[i] == nil"
// branch, which must substitute an empty string rather than the literal word "<nil>".
type nilifyMasker struct{}

func (nilifyMasker) MaskRow(_ context.Context, cols []mask.Column, _ [][]byte) ([][]byte, error) {
	return make([][]byte, len(cols)), nil
}

func TestMaskDocuments_NilMaskedValueBecomesEmptyString(t *testing.T) {
	docs := []map[string]any{{"note": "secret"}}
	out, err := maskDocuments(context.Background(), nilifyMasker{}, nil, nil, "", docs)
	if err != nil {
		t.Fatal(err)
	}
	if out[0]["note"] != "" {
		t.Fatalf("expected a nil masked leaf to become an empty string, got %v", out[0]["note"])
	}
}

// fakeDetector reports every value containing "SECRET" as a positive PII match — a minimal stand-in
// for mask.Remote's Detect (see executor.go's Options.Detector) used to exercise proposeLeaf.
type fakeDetector struct {
	calls int
}

func (d *fakeDetector) Detect(_ context.Context, text string) (string, float64, bool) {
	d.calls++
	if text == "SECRET" {
		return "custom_category", 0.9, true
	}
	return "", 0, false
}

// TestMaskRows_ProposesLabelsForFreeTextDetectorMatches exercises proposeLeaf via maskRows: a
// free-text column whose value the detector flags gets a SourceProposed label Put into the store,
// keyed on (objID, column). Non-free-text columns and non-matching values must not propose anything.
func TestMaskRows_ProposesLabelsForFreeTextDetectorMatches(t *testing.T) {
	det := &fakeDetector{}
	store := label.NewMemStore()
	rows := []map[string]any{{"note": "SECRET", "other": "nothing interesting", "id": 1}}
	cols := []string{"note", "other", "id"}
	spy := &pathSpyMasker{}
	_, err := maskRows(context.Background(), spy, det, store, "org1:postgres:app:app", cols, rows)
	if err != nil {
		t.Fatal(err)
	}
	l, ok, err := store.Lookup(context.Background(), "org1:postgres:app:app", "note")
	if err != nil {
		t.Fatal(err)
	}
	if !ok {
		t.Fatal("expected a proposed label for the detector-matched free-text column")
	}
	if l.Source != label.SourceProposed || l.Category != "custom_category" {
		t.Fatalf("unexpected proposed label: %+v", l)
	}
	if _, ok, _ := store.Lookup(context.Background(), "org1:postgres:app:app", "other"); ok {
		t.Fatal("expected no proposal for a non-matching value")
	}
	if _, ok, _ := store.Lookup(context.Background(), "org1:postgres:app:app", "id"); ok {
		t.Fatal("expected no proposal for a non-free-text (typed) column")
	}
}

// TestMaskRows_SkipsProposalsWhenObjectIDEmpty confirms propose is gated on objID != "" in addition
// to det/store being set (executor.go's Options.OrgID doc comment: empty OrgID disables path-scoped
// proposing without otherwise affecting masking).
func TestMaskRows_SkipsProposalsWhenObjectIDEmpty(t *testing.T) {
	det := &fakeDetector{}
	store := label.NewMemStore()
	rows := []map[string]any{{"note": "SECRET"}}
	spy := &pathSpyMasker{}
	_, err := maskRows(context.Background(), spy, det, store, "", []string{"note"}, rows)
	if err != nil {
		t.Fatal(err)
	}
	if det.calls != 0 {
		t.Fatalf("expected detector never invoked when objID is empty, got %d calls", det.calls)
	}
}

// TestMaskDocuments_ProposesLabelsForDetectorMatches mirrors the maskRows proposal test for the
// nested-document path (maskDocuments), asserting the proposed label lands under the leaf's full
// resolved path, not its bare key.
func TestMaskDocuments_ProposesLabelsForDetectorMatches(t *testing.T) {
	det := &fakeDetector{}
	store := label.NewMemStore()
	docs := []map[string]any{{"profile": map[string]any{"note": "SECRET"}}}
	spy := &pathSpyMasker{}
	_, err := maskDocuments(context.Background(), spy, det, store, "org1:mongo:app:users", docs)
	if err != nil {
		t.Fatal(err)
	}
	l, ok, err := store.Lookup(context.Background(), "org1:mongo:app:users", "profile.note")
	if err != nil {
		t.Fatal(err)
	}
	if !ok {
		t.Fatal("expected a proposed label at the nested path profile.note")
	}
	if l.Category != "custom_category" {
		t.Fatalf("unexpected label: %+v", l)
	}
}

// TestDeepCopyDoc_ProducesIndependentNestedCopy is the regression-shaped test for deepCopyDoc: a
// mutation to the copy's nested map/slice must never be visible in the original, since
// maskDocuments relies on deepCopyDoc to avoid mutating the caller's document in place.
func TestDeepCopyDoc_ProducesIndependentNestedCopy(t *testing.T) {
	orig := map[string]any{
		"a": map[string]any{"b": "1"},
		"c": []any{map[string]any{"d": "2"}, "plain"},
		"e": nil,
		"f": 42,
	}
	copyOf := deepCopyDoc(orig).(map[string]any)

	// Mutate the copy's nested structures.
	copyOf["a"].(map[string]any)["b"] = "mutated"
	copyOf["c"].([]any)[0].(map[string]any)["d"] = "mutated"
	copyOf["c"].([]any)[1] = "also mutated"

	if orig["a"].(map[string]any)["b"] != "1" {
		t.Fatalf("expected original nested map untouched, got %v", orig["a"])
	}
	if orig["c"].([]any)[0].(map[string]any)["d"] != "2" {
		t.Fatalf("expected original nested slice element untouched, got %v", orig["c"])
	}
	if orig["c"].([]any)[1] != "plain" {
		t.Fatalf("expected original slice scalar untouched, got %v", orig["c"].([]any)[1])
	}
	if copyOf["e"] != nil || copyOf["f"] != 42 {
		t.Fatalf("expected scalar/nil fields copied as-is, got e=%v f=%v", copyOf["e"], copyOf["f"])
	}
}
