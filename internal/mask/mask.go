// Package mask applies PII redaction to result rows before they leave the egress network.
//
// Two layers compose:
//   - Remote (default) — calls an external analyze/anonymize service to detect and redact PII.
//   - Overlay (caller-defined) — a column->token map you supply, off by default, layered on top.
//
// The agent runs these locally so raw values are redacted at the source; only masked bytes are
// forwarded back to the client.
package mask

import "context"

// Column describes one result column for masking decisions.
type Column struct {
	// Name is the column/field name as reported by the server (used by the column-aware overlay).
	Name string
	// Text is true when the value bytes are text-format and therefore safe to inspect/redact.
	// Binary-format values are passed through untouched (decoding them is engine-specific).
	Text bool
	// ObjectID identifies the table/collection this column belongs to, opaque to Masker
	// implementations beyond exact-match lookups (e.g. "{orgID}:mongo:{db}:{collection}"). Empty
	// when the caller doesn't know it yet (e.g. today's wire-proxy paths for Postgres/Mongo) — a
	// path-aware Masker must treat an empty ObjectID as "no path-scoped label available" and fall
	// back to bare-key matching, not as a lookup key of its own.
	ObjectID string
	// Path is the resolved, index-erased document path to this leaf (see internal/pathlabel/docpath),
	// e.g. "profile.contact.email". Equal to Name for flat/tabular rows; only meaningfully differs
	// from Name for nested document fields (Mongo). Empty when the caller hasn't walked a nested
	// path (falls back to Name).
	Path string
}

// Masker transforms a single result row. Implementations MUST return a slice the same length as
// row; a nil element represents SQL NULL and should stay nil. Implementations should be
// best-effort: on any internal error they may return the row unchanged rather than failing the
// whole session (the caller still checks the error).
type Masker interface {
	MaskRow(ctx context.Context, cols []Column, row [][]byte) ([][]byte, error)
}

// Noop returns rows unchanged. It is the default when no masking is configured.
type Noop struct{}

// MaskRow implements Masker.
func (Noop) MaskRow(_ context.Context, _ []Column, row [][]byte) ([][]byte, error) {
	return row, nil
}
