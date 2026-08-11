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
	// FreeText is true when the column's declared type is genuinely free-form text (varchar, text,
	// json, ...), the only case a free-text PII detector (Presidio DATE_TIME/PERSON/etc.) should run
	// against. Zero value is false, so every existing caller must set this explicitly true to keep
	// today's behavior (Mongo/MySQL/dbquery/k8sexec callers that don't resolve a schema type do so
	// unconditionally). A caller that DOES know a typed schema (the Postgres wire proxy, via
	// RowDescription's typeOID) must set this false for date/time/numeric/boolean/uuid/binary
	// columns, whose values are drawn from a fixed, driver-decoded wire format: a detector
	// confidently misclassifying an ordinary timestamp as DATE_TIME and redacting it produces a
	// value the client's type decoder can no longer parse, corrupting the response rather than just
	// over-redacting free text.
	FreeText bool
	// TypeKind optionally refines FreeText==false with the column's actual type shape, letting
	// PathOverlay substitute a type-valid placeholder for a *confirmed* label's redaction request
	// instead of unconditionally skipping the column — see
	// docs/PATH_LABEL_IDENTITY_GAPS_DESIGN.md's Gap B. Zero value (TypeKindUnspecified) means "no
	// type detail beyond FreeText" — every existing caller that only ever set FreeText needs no
	// change; PathOverlay falls back to today's unconditional-skip behavior for FreeText==false,
	// TypeKindUnspecified columns, exactly as before this field existed. Content detectors
	// (mask.Remote) and the flat Overlay layer ignore this field entirely — it only ever changes
	// PathOverlay's behavior for a confirmed (manual/platform) label, never a probabilistic guess.
	TypeKind TypeKind
}

// TypeKind classifies a non-free-text column's wire type shape, for PathOverlay's type-valid
// placeholder substitution (see Column.TypeKind and docs/PATH_LABEL_IDENTITY_GAPS_DESIGN.md's
// Gap B). Meaningless when Column.FreeText is true.
type TypeKind int

const (
	// TypeKindUnspecified means "no type detail beyond FreeText" — the zero value, so every
	// existing caller that never set this field keeps today's behavior unchanged.
	TypeKindUnspecified TypeKind = iota
	TypeKindDate                 // date/time/timestamp/timestamptz/interval
	TypeKindNumeric              // int/float/decimal/numeric
	TypeKindBool
	TypeKindUUID
	// TypeKindObjectID is Mongo's 12-byte BSON ObjectID — kept distinct from TypeKindUUID (a
	// 36-character string-form UUID) since the two have different canonical text/binary shapes.
	// PathOverlay's typeValidPlaceholder for this kind is never actually used: Mongo substitutes
	// its own 12-byte-binary placeholder directly (BSON values aren't the plain-string wire format
	// PathOverlay's placeholder table assumes) — this constant exists so mask.Column can still
	// carry TypeKind for a BSON ObjectID field, and so a future SQL-side "uuid-shaped column
	// backed by a binary type" caller has a distinct kind to reach for instead of overloading
	// TypeKindUUID's string-placeholder semantics.
	TypeKindObjectID
)

// Masker transforms a single result row. Implementations MUST return a slice the same length as
// row; a nil element represents SQL NULL and should stay nil. Implementations should be
// best-effort: on any internal error they may return the row unchanged rather than failing the
// whole session (the caller still checks the error).
type Masker interface {
	MaskRow(ctx context.Context, cols []Column, row [][]byte) ([][]byte, error)
}

// partialKeepChars/partialMaskChar are the fixed parameters for partialMask — no per-rule override
// in this pass (see docs/REDACTION_COMPETITIVE_ANALYSIS.md's backlog item 2): a single sensible
// default ("keep the last 4 characters") covers the common "show last 4 digits of an SSN/card to a
// support agent" case this feature targets.
const (
	partialKeepChars = 4
	partialMaskChar  = '*'
)

// partialMask keeps the last partialKeepChars bytes of value and replaces everything before them
// with partialMaskChar, e.g. "123-45-6789" -> "*******6789". Operates on raw bytes, not runes —
// matches every other layer's byte-oriented value handling (callers only ever reach this after
// mask.Column.Text/FreeText have already gated out non-text/binary values). A value shorter than or
// equal to partialKeepChars is masked in full — "reveal the whole thing because it happened to be
// short" is a worse default than "mask all of it."
func partialMask(value []byte) []byte {
	if len(value) <= partialKeepChars {
		out := make([]byte, len(value))
		for i := range out {
			out[i] = partialMaskChar
		}
		return out
	}
	out := make([]byte, len(value))
	maskLen := len(value) - partialKeepChars
	for i := 0; i < maskLen; i++ {
		out[i] = partialMaskChar
	}
	copy(out[maskLen:], value[maskLen:])
	return out
}

// Noop returns rows unchanged. It is the default when no masking is configured.
type Noop struct{}

// MaskRow implements Masker.
func (Noop) MaskRow(_ context.Context, _ []Column, row [][]byte) ([][]byte, error) {
	return row, nil
}
