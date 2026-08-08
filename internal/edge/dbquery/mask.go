package dbquery

import (
	"context"
	"fmt"

	"github.com/curlix-io/skybridge/internal/mask"
	"github.com/curlix-io/skybridge/internal/pathlabel/docpath"
)

func maskRows(ctx context.Context, masker mask.Masker, objID string, cols []string, rows []map[string]any) ([]map[string]any, error) {
	if masker == nil {
		return rows, nil
	}
	maskCols := make([]mask.Column, len(cols))
	for i, c := range cols {
		maskCols[i] = mask.Column{Name: c, Path: c, ObjectID: objID, Text: true}
	}
	out := make([]map[string]any, 0, len(rows))
	for _, row := range rows {
		raw := make([][]byte, len(cols))
		for i, col := range cols {
			v := row[col]
			if v == nil {
				raw[i] = nil
				continue
			}
			raw[i] = []byte(fmt.Sprint(v))
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
func maskDocuments(ctx context.Context, masker mask.Masker, objID string, docs []map[string]any) ([]map[string]any, error) {
	if masker == nil {
		return docs, nil
	}
	out := make([]map[string]any, 0, len(docs))
	for _, doc := range docs {
		leaves := docpath.Walk(doc)
		maskCols := make([]mask.Column, 0, len(leaves))
		raw := make([][]byte, 0, len(leaves))
		for _, l := range leaves {
			if l.IsKey {
				continue // key-leaf redaction (§3.1.1) is a future extension, not handled here yet
			}
			maskCols = append(maskCols, mask.Column{Name: l.Key, Path: l.Path, ObjectID: objID, Text: true})
			raw = append(raw, []byte(l.Value))
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
