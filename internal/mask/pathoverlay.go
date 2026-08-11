package mask

import (
	"context"
	"strings"

	"github.com/curlix-io/skybridge/internal/pathlabel/label"
)

// PathOverlay is a Store-backed masking layer: it looks up a confirmed label for each column's
// resolved path, falling back to a bare-key match when no path-scoped label exists or ObjectID is
// unknown (e.g. wire-proxy call sites that don't yet resolve table/collection identity). This
// supersedes Overlay's flat column->token map (which becomes, in effect, a store populated entirely
// with MatchKeyAnyDepth labels) without dropping any of Overlay's existing coverage: a miss here
// behaves exactly like a miss in Overlay always did.
type PathOverlay struct {
	store label.Store
	// metrics records analyzed/masked outcome counts (pure metadata, never values). Nil is a safe
	// no-op — see MetricsRecorder's doc comment in remote.go.
	metrics MetricsRecorder
	// connectionKey identifies this agent's connection for metrics (metrics.ConnectionKey format).
	// Only meaningful when metrics is non-nil.
	connectionKey string
}

// NewPathOverlay wraps store as a Masker. A nil store yields a permanent no-op.
func NewPathOverlay(store label.Store) *PathOverlay {
	return &PathOverlay{store: store}
}

// NewPathOverlayWithMetrics is NewPathOverlay plus a metrics recorder for the Data Classification
// dashboard. metrics may be nil (no-op, same as NewPathOverlay).
func NewPathOverlayWithMetrics(store label.Store, metrics MetricsRecorder, connectionKey string) *PathOverlay {
	return &PathOverlay{store: store, metrics: metrics, connectionKey: connectionKey}
}

// seeder is implemented by Store backends (e.g. pathlabel/remotestore.Store) that need to be told
// about an ObjectID before they have any label for it, so a background sync loop knows to start
// pulling confirmed labels for that object. Optional: most Store implementations (MemStore, a
// future direct-DB store) have no such need and don't implement it.
type seeder interface {
	SeedObject(objectID string)
}

// MaskRow implements Masker by replacing values whose column resolves to a confirmed
// full_redact/partial_mask label, by path first and then by bare key name.
//
// A FreeText==false column is only ever considered when col.TypeKind is set (Gap B,
// docs/PATH_LABEL_IDENTITY_GAPS_DESIGN.md) — and even then, lookupMasked only substitutes a
// type-valid placeholder for a *confirmed* label's explicit redaction request, never for a probing
// content-detector guess. FreeText==false with TypeKind unset behaves exactly as before this field
// existed: skipped unconditionally, since an unlabelled/proposed-only typed column has no
// type-valid placeholder to substitute anyway.
func (p *PathOverlay) MaskRow(ctx context.Context, cols []Column, row [][]byte) ([][]byte, error) {
	if p == nil || p.store == nil {
		return row, nil
	}
	for i := range row {
		if i >= len(cols) || row[i] == nil || !cols[i].Text {
			continue
		}
		if !cols[i].FreeText && cols[i].TypeKind == TypeKindUnspecified {
			continue
		}
		masked, ok, err := p.lookupMasked(ctx, cols[i], row[i])
		if err != nil {
			return nil, err
		}
		if ok {
			row[i] = masked
		}
	}
	return row, nil
}

// lookupMasked resolves the replacement bytes for col given its original value, if any — either a
// fixed token/placeholder or, for a free-text column with a confirmed partial_mask profile, the
// value itself run through partialMask. value is the byte length attributed to RecordMasked as pure
// metadata (never the value itself), matching the "counts, entity types, byte counts" constraint on
// what may ever leave the customer's network.
func (p *PathOverlay) lookupMasked(ctx context.Context, col Column, value []byte) ([]byte, bool, error) {
	if col.ObjectID == "" {
		return nil, false, nil
	}
	if sd, ok := p.store.(seeder); ok {
		// Tell a sync-backed Store about this object on its very first lookup, so its background
		// poller starts pulling confirmed labels for it even before any label has been proposed or
		// confirmed — otherwise an object that only ever gets confirmed/platform labels (no local
		// proposals ever Put) would never be discovered by the poller's "known objects" set.
		sd.SeedObject(col.ObjectID)
	}
	if p.metrics != nil {
		// "Analyzed" here means "a label lookup was attempted for this value" — this fires exactly
		// once per value, before either the path-scoped or bare-key lookup below, regardless of hit
		// (redact=true), do_not_mask (hit but redact=false — still a real "analyzed, explicitly not
		// masked" outcome per the pathlabel design doc's three-way profile split), or miss.
		p.metrics.RecordAnalyzed(p.connectionKey, "field_rule")
	}
	path := col.Path
	if path == "" {
		path = col.Name
	}
	if l, ok, err := p.store.Lookup(ctx, col.ObjectID, path); err != nil {
		return nil, false, err
	} else if ok && isConfirmed(l.Source) {
		if masked, redact := p.applyProfile(l, col, value); redact {
			return masked, true, nil
		}
		return nil, false, nil
	}

	key := strings.ToLower(strings.TrimSpace(col.Name))
	if key == "" {
		return nil, false, nil
	}
	l, ok, err := p.store.Lookup(ctx, col.ObjectID, key)
	if err != nil {
		return nil, false, err
	}
	if !ok || !isConfirmed(l.Source) {
		return nil, false, nil
	}
	masked, redact := p.applyProfile(l, col, value)
	return masked, redact, nil
}

// applyProfile resolves l's Profile into the actual replacement bytes for value, recording a
// RecordMasked outcome when it redacts.
func (p *PathOverlay) applyProfile(l label.Label, col Column, value []byte) ([]byte, bool) {
	action, tok := profileAction(l.Profile, col.FreeText, col.TypeKind)
	switch action {
	case actionNone:
		return nil, false
	case actionPartial:
		p.recordMaskedIfEnabled(l.Category, len(value))
		return partialMask(value), true
	default: // actionToken
		p.recordMaskedIfEnabled(l.Category, len(value))
		return []byte(tok), true
	}
}

// recordMaskedIfEnabled reports one field_rule masked value under category (the Object Field
// Rules taxonomy, e.g. "email_fields" — distinct from Presidio's entity types).
func (p *PathOverlay) recordMaskedIfEnabled(category string, byteCount int) {
	if p.metrics == nil {
		return
	}
	p.metrics.RecordMasked(p.connectionKey, category, byteCount, "field_rule")
}

func isConfirmed(s label.Source) bool {
	return s == label.SourceManual || s == label.SourcePlatform
}

// typeValidPlaceholder maps a TypeKind to a replacement value that parses under every driver's
// decoder for that type, per docs/PATH_LABEL_IDENTITY_GAPS_DESIGN.md's Gap B — substituting the
// string "[redacted]" into a typed wire slot corrupts the client's type decoder rather than just
// masking the value, so a confirmed label's redaction on a typed column needs a type-valid value
// instead. Only consulted for FreeText==false columns with a non-zero TypeKind (see MaskRow); a
// TypeKind this map has no entry for (a future addition to the enum without a placeholder yet)
// falls back to profileAction's own default of leaving the column unmasked — never a string
// token that would corrupt it.
//
// TypeKindObjectID's entry is a placeholder for the redact/don't-redact *signal* only — a caller in
// this map's own package (a hypothetical SQL binary-uuid column) would need a real substitute
// value here, but Mongo's bsonMasker (internal/wire/mongo) discards this string entirely and
// substitutes its own fixed-width, zero-valued 12-byte BSON encoding instead, since a BSON
// ObjectID's wire representation is never a plain string this map's shape can express — see
// mongo.maskScalar's doc comment for why.
var typeValidPlaceholder = map[TypeKind]string{
	TypeKindDate:     "0001-01-01",
	TypeKindNumeric:  "0",
	TypeKindBool:     "false",
	TypeKindUUID:     "00000000-0000-0000-0000-000000000000",
	TypeKindObjectID: "000000000000000000000000",
}

// labelAction selects what applyProfile does for a confirmed label's Profile.
type labelAction int

const (
	// actionNone means "confirmed label present, but explicitly not masked" (do_not_mask, or an
	// unmappable typed-column TypeKind).
	actionNone labelAction = iota
	// actionToken means substitute a fixed token/placeholder (see profileAction's tok return).
	actionToken
	// actionPartial means keep the value's last few characters, masking the rest (partialMask) —
	// only ever returned for a free-text column; typed columns always get actionToken/actionNone,
	// per docs/PATH_LABEL_IDENTITY_GAPS_DESIGN.md's Gap B non-goal.
	actionPartial
)

// profileAction maps a Label's Profile to an action, per label's vendor-agnostic three-way split
// (full_redact / partial_mask / do_not_mask), accounting for the column's type shape. For a
// free-text column (freeText==true), an empty or unknown Profile is treated as full_redact
// (Category alone — "this path is labelled" — is already a stronger signal than an unlabelled path,
// so the safe default is to act on it), and partial_mask now applies a real partial-mask transform
// to the value (see partialMask) rather than a fixed "[masked]" token.
//
// For a typed, non-free-text column, a confirmed redaction request must use a type-valid
// placeholder instead of a string token (see typeValidPlaceholder) — and partial_mask has no
// defined meaning for a typed value yet (docs/PATH_LABEL_IDENTITY_GAPS_DESIGN.md's Gap B
// non-goals), so it's treated the same as full_redact here rather than silently doing nothing or
// applying a string-shaped token that would corrupt the column. A TypeKind with no
// typeValidPlaceholder entry has no safe substitute value, so it's left unmasked (actionNone)
// rather than guessing — the same fail-safe-toward-not-corrupting posture the original FreeText
// guard had.
func profileAction(profile string, freeText bool, kind TypeKind) (labelAction, string) {
	if freeText {
		switch profile {
		case "do_not_mask":
			return actionNone, ""
		case "partial_mask":
			return actionPartial, ""
		default:
			return actionToken, "[redacted]"
		}
	}
	if profile == "do_not_mask" {
		return actionNone, ""
	}
	tok, ok := typeValidPlaceholder[kind]
	if !ok {
		return actionNone, ""
	}
	return actionToken, tok
}

var _ Masker = (*PathOverlay)(nil)
