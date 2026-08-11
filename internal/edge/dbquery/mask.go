package dbquery

import (
	"context"
	"fmt"
	"time"

	"github.com/curlix-io/skybridge/internal/mask"
	"github.com/curlix-io/skybridge/internal/pathlabel/docpath"
	"github.com/curlix-io/skybridge/internal/pathlabel/label"
)

// detector matches mask.Remote's Detect method (see executor.go's Options.Detector) — kept as a
// local interface so this file doesn't import the concrete mask.Remote type just for a method set.
type detector interface {
	Detect(ctx context.Context, text string) (category string, confidence float64, ok bool)
}

// proposeLeaf runs det against value, if set, and Puts a SourceProposed label into store for the
// matching leaf when det reports a positive match. Both det and store must be non-nil (checked by
// the caller) — this is a small helper shared by maskRows and maskDocuments rather than a
// standalone exported function, since neither caller has a reason to invoke it independently.
func proposeLeaf(ctx context.Context, det detector, store label.Store, objID, fieldPath, value string) {
	category, confidence, ok := det.Detect(ctx, value)
	if !ok {
		return
	}
	_ = store.Put(ctx, label.Label{
		ObjectID:       objID,
		FieldPath:      fieldPath,
		MatchMode:      label.MatchPath,
		Category:       category,
		Source:         label.SourceProposed,
		Confidence:     confidence,
		SampleCount:    1,
		LastObservedAt: time.Now(),
	})
}

// isFreeTextValue reports whether v's Go type (as returned by database/sql's Scan across the
// postgres/mysql/mongo/snowflake drivers this package's executors use) is genuinely free-form text
// eligible for a free-text PII detector — never a typed date/numeric/boolean value. Presidio's
// DATE_TIME/numeric recognizers can confidently misclassify an ordinary timestamp or number as PII
// and redact it, and since maskRows re-stringifies every value uniformly via fmt.Sprint, a redacted
// placeholder there silently replaces the real value with no wire-level type to violate — unlike
// the postgres/mysql wire-proxy engines, there's no client type-decoder to visibly crash, so this
// class of corruption would otherwise pass silently. mysql's driver commonly returns numeric/bool
// columns as []byte (text protocol), which is indistinguishable from a genuine text column here;
// accepting that gap on this driver is a known tradeoff, not something this check can resolve
// without column-type metadata this function doesn't have.
func isFreeTextValue(v any) bool {
	switch v.(type) {
	case time.Time, *time.Time:
		return false
	case bool, *bool:
		return false
	case int, int8, int16, int32, int64,
		uint, uint8, uint16, uint32, uint64,
		float32, float64:
		return false
	default:
		return true
	}
}

func maskRows(ctx context.Context, masker mask.Masker, det detector, store label.Store, objID string, cols []string, rows []map[string]any) ([]map[string]any, error) {
	if masker == nil {
		return rows, nil
	}
	out := make([]map[string]any, 0, len(rows))
	propose := det != nil && store != nil && objID != ""
	for _, row := range rows {
		maskCols := make([]mask.Column, len(cols))
		raw := make([][]byte, len(cols))
		for i, col := range cols {
			v := row[col]
			maskCols[i] = mask.Column{Name: col, Path: col, ObjectID: objID, Text: true, FreeText: isFreeTextValue(v)}
			if v == nil {
				raw[i] = nil
				continue
			}
			raw[i] = []byte(fmt.Sprint(v))
			if propose && maskCols[i].FreeText {
				proposeLeaf(ctx, det, store, objID, col, string(raw[i]))
			}
		}
		masked, err := masker.MaskRow(ctx, maskCols, raw)
		if err != nil {
			return nil, err
		}
		mrow := make(map[string]any, len(cols))
		for i, col := range cols {
			if masked[i] == nil {
				mrow[col] = nil
			} else {
				mrow[col] = string(masked[i])
			}
		}
		out = append(out, mrow)
	}
	return out, nil
}

// maskDocuments masks every string leaf of each nested document, per its resolved docpath (see
// internal/pathlabel/docpath) rather than flattening to top-level field names first — this is what
// lets a path-scoped label distinguish e.g. "order.total" from "user.total" (pathlabel design doc
// §3.3), and what lets a nested "profile.contact.email" carry its own label independent of any
// top-level field happening to share the name "email".
func maskDocuments(ctx context.Context, masker mask.Masker, det detector, store label.Store, objID string, docs []map[string]any) ([]map[string]any, error) {
	if masker == nil {
		return docs, nil
	}
	propose := det != nil && store != nil && objID != ""
	out := make([]map[string]any, 0, len(docs))
	for _, doc := range docs {
		leaves := docpath.Walk(doc)
		maskCols := make([]mask.Column, 0, len(leaves))
		raw := make([][]byte, 0, len(leaves))
		for _, l := range leaves {
			if l.IsKey {
				continue // key-leaf redaction (§3.1.1) is a future extension, not handled here yet
			}
			maskCols = append(maskCols, mask.Column{Name: l.Key, Path: l.Path, ObjectID: objID, Text: true, FreeText: true})
			raw = append(raw, []byte(l.Value))
			if propose {
				proposeLeaf(ctx, det, store, objID, l.Path, l.Value)
			}
		}
		masked, err := masker.MaskRow(ctx, maskCols, raw)
		if err != nil {
			return nil, err
		}
		if len(masked) != len(raw) {
			return nil, fmt.Errorf("dbquery: masker returned %d values for %d leaves", len(masked), len(raw))
		}
		mdoc := deepCopyDoc(doc).(map[string]any)
		// Replace visits non-key leaves in the exact same order Walk produced them above (both use
		// sortedKeys + in-order array traversal), so a plain position counter lines masked[] back up
		// with the leaf it belongs to — no path/value matching needed, and it stays correct even
		// when two leaves share the same path and value (e.g. a repeated string in an array).
		i := 0
		docpath.Replace(mdoc, func(l docpath.Leaf) bool { return !l.IsKey }, func(l docpath.Leaf) string {
			v := masked[i]
			i++
			if v == nil {
				return ""
			}
			return string(v)
		})
		out = append(out, mdoc)
	}
	return out, nil
}

func deepCopyDoc(v any) any {
	switch x := v.(type) {
	case map[string]any:
		out := make(map[string]any, len(x))
		for k, vv := range x {
			out[k] = deepCopyDoc(vv)
		}
		return out
	case []any:
		out := make([]any, len(x))
		for i, vv := range x {
			out[i] = deepCopyDoc(vv)
		}
		return out
	default:
		return x
	}
}
