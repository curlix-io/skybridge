package mask

import (
	"context"
	"strings"
	"sync/atomic"
)

// Overlay is the caller-defined layer: a PII schema projected onto column names. It is OFF by
// default (an empty rule set is a no-op) and is applied on top of the default remote masker. Keys
// are matched case-insensitively against the column name.
//
// The rule set is hot-swappable via Replace so a control-plane poller (see the agent's overlay
// source) can refresh it while sessions are in flight; reads are lock-free via an atomic pointer.
type Overlay struct {
	// rules maps a lowercased column name to its replacement token (e.g. "email" -> "[redacted]").
	rules atomic.Pointer[map[string]string]
}

func normalizeRules(rules map[string]string) map[string]string {
	norm := make(map[string]string, len(rules))
	for k, v := range rules {
		key := strings.ToLower(strings.TrimSpace(k))
		if key == "" {
			continue
		}
		norm[key] = v
	}
	return norm
}

// NewOverlay builds an Overlay from a column->token map. A nil/empty map yields a no-op overlay
// (which can later be populated via Replace).
func NewOverlay(rules map[string]string) *Overlay {
	o := &Overlay{}
	norm := normalizeRules(rules)
	o.rules.Store(&norm)
	return o
}

// Replace atomically swaps the active rule set. Safe to call concurrently with MaskRow.
func (o *Overlay) Replace(rules map[string]string) {
	norm := normalizeRules(rules)
	o.rules.Store(&norm)
}

func (o *Overlay) current() map[string]string {
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
		if i >= len(cols) || row[i] == nil || !cols[i].Text {
			continue
		}
		if tok, ok := rules[strings.ToLower(cols[i].Name)]; ok {
			row[i] = []byte(tok)
		}
	}
	return row, nil
}
