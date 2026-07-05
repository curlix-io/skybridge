package dbquery

import (
	"context"
	"fmt"

	"github.com/curlix-io/skybridge/internal/mask"
)

func maskRows(ctx context.Context, masker mask.Masker, cols []string, rows []map[string]any) ([]map[string]any, error) {
	if masker == nil {
		return rows, nil
	}
	maskCols := make([]mask.Column, len(cols))
	for i, c := range cols {
		maskCols[i] = mask.Column{Name: c, Text: true}
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

func maskDocuments(ctx context.Context, masker mask.Masker, docs []map[string]any) ([]map[string]any, error) {
	if masker == nil {
		return docs, nil
	}
	out := make([]map[string]any, 0, len(docs))
	for _, doc := range docs {
		cols := make([]string, 0, len(doc))
		for k := range doc {
			cols = append(cols, k)
		}
		// stable column order for masking
		for i := 0; i < len(cols); i++ {
			for j := i + 1; j < len(cols); j++ {
				if cols[j] < cols[i] {
					cols[i], cols[j] = cols[j], cols[i]
				}
			}
		}
		maskCols := make([]mask.Column, len(cols))
		raw := make([][]byte, len(cols))
		for i, c := range cols {
			maskCols[i] = mask.Column{Name: c, Text: true}
			v := doc[c]
			if v == nil {
				raw[i] = nil
			} else {
				raw[i] = []byte(fmt.Sprint(v))
			}
		}
		masked, err := masker.MaskRow(ctx, maskCols, raw)
		if err != nil {
			return nil, err
		}
		mrow := make(map[string]any, len(cols))
		for i, c := range cols {
			if masked[i] == nil {
				mrow[c] = nil
			} else {
				mrow[c] = string(masked[i])
			}
		}
		out = append(out, mrow)
	}
	return out, nil
}
