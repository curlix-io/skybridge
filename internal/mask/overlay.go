package mask

import (
	"context"
	"strings"
	"sync/atomic"
)

// OverlayRule is one column's masking rule. Exactly one of Token/Partial is meaningful: Partial
// (an explicit, non-empty opt-in) takes precedence, otherwise Token is used as a full-value
// replacement — the original, and still default, behavior.
type OverlayRule struct {
	// Token is the full-value replacement string, e.g. "[redacted]".
	Token string
	// Partial, when true, keeps the value's last few characters and masks the rest (see
	// partialMask) instead of a full-value replacement.
	Partial bool
}

// Overlay is the caller-defined layer: a PII schema projected onto column names. It is OFF by
// default (an empty rule set is a no-op) and is applied on top of the default remote masker. Keys
// are matched case-insensitively against the column name.
//
// The rule set is hot-swappable via Replace/ReplaceRules so a control-plane poller (see the agent's
// overlay source) can refresh it while sessions are in flight; reads are lock-free via an atomic
// pointer.
type Overlay struct {
	// rules maps a lowercased column name to its rule (e.g. "email" -> full-replace "[redacted]").
	rules atomic.Pointer[map[string]OverlayRule]
}

func normalizeRules(rules map[string]OverlayRule) map[string]OverlayRule {
	norm := make(map[string]OverlayRule, len(rules))
	for k, v := range rules {
		key := strings.ToLower(strings.TrimSpace(k))
		if key == "" {
			continue
		}
		norm[key] = v
	}
	return norm
}

// tokenRules wraps a plain column->token map as OverlayRule{Token: ...} entries — the shape every
// existing caller (static SKYBRIDGE_PII_OVERLAY, the dynamic control-plane overlay source) already
// uses, preserved as a full-value replacement with no behavior change.
func tokenRules(tokens map[string]string) map[string]OverlayRule {
	rules := make(map[string]OverlayRule, len(tokens))
	for k, v := range tokens {
		rules[k] = OverlayRule{Token: v}
	}
	return rules
}

// NewOverlay builds an Overlay from a column->token map (full-value replacement only). A nil/empty
// map yields a no-op overlay (which can later be populated via Replace/ReplaceRules). See
// NewOverlayWithRules for the richer form that also supports partial masking.
func NewOverlay(tokens map[string]string) *Overlay {
	return NewOverlayWithRules(tokenRules(tokens))
}

// NewOverlayWithRules builds an Overlay from a column->rule map, supporting both full-value
// replacement (OverlayRule.Token) and partial masking (OverlayRule.Partial).
func NewOverlayWithRules(rules map[string]OverlayRule) *Overlay {
	o := &Overlay{}
	norm := normalizeRules(rules)
	o.rules.Store(&norm)
	return o
}

// Replace atomically swaps the active rule set with a column->token map (full-value replacement
// only — see ReplaceRules for the richer form). Safe to call concurrently with MaskRow.
func (o *Overlay) Replace(tokens map[string]string) {
	o.ReplaceRules(tokenRules(tokens))
}

// ReplaceRules atomically swaps the active rule set. Safe to call concurrently with MaskRow.
func (o *Overlay) ReplaceRules(rules map[string]OverlayRule) {
	norm := normalizeRules(rules)
	o.rules.Store(&norm)
}

func (o *Overlay) current() map[string]OverlayRule {
	if p := o.rules.Load(); p != nil {
		return *p
	}
	return nil
}

// Enabled reports whether any overlay rules are currently configured.
func (o *Overlay) Enabled() bool { return len(o.current()) > 0 }

// MaskRow implements Masker by replacing values whose column name matches a configured rule.
func (o *Overlay) MaskRow(_ context.Context, cols []Column, row [][]byte) ([][]byte, error) {
	rules := o.current()
	if len(rules) == 0 {
		return row, nil
	}
	for i := range row {
		if i >= len(cols) || row[i] == nil || !cols[i].Text || !cols[i].FreeText {
			continue
		}
		rule, ok := rules[strings.ToLower(cols[i].Name)]
		if !ok {
			continue
		}
		if rule.Partial {
			row[i] = partialMask(row[i])
		} else {
			row[i] = []byte(rule.Token)
		}
	}
	return row, nil
}
