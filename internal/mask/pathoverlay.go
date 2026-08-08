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
}

// NewPathOverlay wraps store as a Masker. A nil store yields a permanent no-op.
func NewPathOverlay(store label.Store) *PathOverlay {
	return &PathOverlay{store: store}
}

// MaskRow implements Masker by replacing values whose column resolves to a confirmed
// full_redact/partial_mask label, by path first and then by bare key name.
func (p *PathOverlay) MaskRow(ctx context.Context, cols []Column, row [][]byte) ([][]byte, error) {
	if p == nil || p.store == nil {
		return row, nil
	}
	for i := range row {
		if i >= len(cols) || row[i] == nil || !cols[i].Text {
			continue
		}
		tok, ok, err := p.lookupToken(ctx, cols[i])
		if err != nil {
			return nil, err
		}
		if ok {
			row[i] = []byte(tok)
		}
	}
	return row, nil
}

func (p *PathOverlay) lookupToken(ctx context.Context, col Column) (string, bool, error) {
	if col.ObjectID == "" {
		return "", false, nil
	}
	path := col.Path
	if path == "" {
		path = col.Name
	}
	if l, ok, err := p.store.Lookup(ctx, col.ObjectID, path); err != nil {
		return "", false, err
	} else if ok && isConfirmed(l.Source) {
		if tok, redact := profileToken(l.Profile); redact {
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
	return tok, redact, nil
}

func isConfirmed(s label.Source) bool {
	return s == label.SourceManual || s == label.SourcePlatform
}

// profileToken maps a Label's Profile to a replacement token, per label's vendor-agnostic
// three-way split (full_redact / partial_mask / do_not_mask). An empty or unknown
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
