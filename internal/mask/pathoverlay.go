package mask

import (
	"context"
	"strings"

	"github.com/curlix-io/skybridge/internal/pathlabel/label"
)

// PathOverlay is a Store-backed masking layer: it looks up a confirmed label for each column's
// resolved path, falling back to a bare-key match when no path-scoped label exists or ObjectID is
// unknown (e.g. wire-proxy call sites that don't yet resolve table/collection identity). This is
// the lookup order from the pathlabel design doc §3.3, steps 2-3 — it supersedes Overlay's flat
// column->token map (which becomes, in effect, a store populated entirely with MatchKeyAnyDepth
// labels) without dropping any of Overlay's existing coverage: a miss here behaves exactly like a
// miss in Overlay always did.
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
func (p *PathOverlay) MaskRow(ctx context.Context, cols []Column, row [][]byte) ([][]byte, error) {
	if p == nil || p.store == nil {
		return row, nil
	}
	for i := range row {
		// FreeText excludes typed non-text columns (date/numeric/uuid/...) the same way Remote does
		// (see mask.Column.FreeText doc comment): any string token substituted into a wire slot the
		// client will type-decode corrupts the response, whether the redaction came from a detector
		// guess or, as here, an admin-confirmed field-rule label. Masking a labelled typed column
		// (e.g. a "date_of_birth" timestamptz) would need a type-valid replacement value, not a
		// "[redacted]" string — that's a separate, not-yet-built feature, not a relaxation of this
		// guard.
		if i >= len(cols) || row[i] == nil || !cols[i].Text || !cols[i].FreeText {
			continue
		}
		originalLen := len(row[i])
		tok, ok, err := p.lookupToken(ctx, cols[i], originalLen)
		if err != nil {
			return nil, err
		}
		if ok {
			row[i] = []byte(tok)
		}
	}
	return row, nil
}

// lookupToken resolves the replacement token for col, if any. originalLen is the byte length of
// the value being looked up — pure metadata (never the value itself) attributed to RecordMasked so
// the dashboard can show masked byte volume, matching the "counts, entity types, byte counts"
// constraint on what may ever leave the customer's network.
func (p *PathOverlay) lookupToken(ctx context.Context, col Column, originalLen int) (string, bool, error) {
	if col.ObjectID == "" {
		return "", false, nil
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
		return "", false, err
	} else if ok && isConfirmed(l.Source) {
		if tok, redact := profileToken(l.Profile); redact {
			p.recordMaskedIfEnabled(l.Category, originalLen)
			return tok, true, nil
		}
		return "", false, nil
	}

	key := strings.ToLower(strings.TrimSpace(col.Name))
	if key == "" {
		return "", false, nil
	}
	l, ok, err := p.store.Lookup(ctx, col.ObjectID, key)
	if err != nil {
		return "", false, err
	}
	if !ok || !isConfirmed(l.Source) {
		return "", false, nil
	}
	tok, redact := profileToken(l.Profile)
	if redact {
		p.recordMaskedIfEnabled(l.Category, originalLen)
	}
	return tok, redact, nil
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

// profileToken maps a Label's Profile to a replacement token, per the pathlabel design doc's
// vendor-agnostic three-way split (full_redact / partial_mask / do_not_mask). An empty or unknown
// Profile is treated as full_redact, since Category alone ("this path is labelled") is already a
// stronger signal than an unlabelled path — the safe default is to act on it, not to require a
// Profile a caller may not always set.
func profileToken(profile string) (string, bool) {
	switch profile {
	case "do_not_mask":
		return "", false
	case "partial_mask":
		return "[masked]", true
	default:
		return "[redacted]", true
	}
}

var _ Masker = (*PathOverlay)(nil)
