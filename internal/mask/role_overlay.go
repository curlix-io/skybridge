package mask

import (
	"context"
	"sync/atomic"
)

// resourceRoleIDKey is the context key carrying the resource_role_id that authorized the current
// connection (set once per stream in agent.serveStream from the already-decoded, server-resolved
// tunnel.OpenMeta.ResourceRoleID — never a client-supplied value). MaskRow already threads ctx
// through every layer (Remote, PathOverlay, Overlay, Chain), so no wire-engine or Chain change is
// needed to make it available here.
type resourceRoleIDKey struct{}

// WithResourceRoleID attaches the resource_role_id for the current connection to ctx, so a
// RoleOverlay masker (or anything else layered into the chain later) can select connection-specific
// behavior. An empty roleID is a no-op (ResourceRoleIDFromContext returns "" either way).
func WithResourceRoleID(ctx context.Context, roleID string) context.Context {
	if roleID == "" {
		return ctx
	}
	return context.WithValue(ctx, resourceRoleIDKey{}, roleID)
}

// ResourceRoleIDFromContext returns the resource_role_id attached by WithResourceRoleID, or "" when
// none was attached (ordinary connections with no matched Resource Role — the common case today).
func ResourceRoleIDFromContext(ctx context.Context) string {
	if ctx == nil {
		return ""
	}
	v, _ := ctx.Value(resourceRoleIDKey{}).(string)
	return v
}

// RoleOverlay is a column->token Overlay that additionally supports a per-resource-role override,
// selected from ctx (see WithResourceRoleID). It implements Masker directly, so it drops into a
// Chain exactly where a plain *Overlay used to.
//
// A connection with no resource_role_id, or one whose role has no override, gets byte-identical
// behavior to a plain Overlay (falls through to the default rule set). This is the role-scoping
// counterpart to Curlix's resource_roles.default_pii_scope: unset for a role -> no override, zero
// behavior change.
type RoleOverlay struct {
	// defaultOverlay is the org-wide overlay every connection uses when its resource_role_id has no
	// override (or carries none at all).
	defaultOverlay *Overlay
	// byRole holds one *Overlay per resource_role_id with a configured override. Replaced wholesale
	// on each control-plane poll refresh (see ReplaceRoleOverlays) — individual entries are never
	// mutated in place, only the map pointer swaps, so a MaskRow in flight always sees a consistent
	// snapshot.
	byRole atomic.Pointer[map[string]*Overlay]
}

// NewRoleOverlay builds a RoleOverlay whose default rule set starts as tokens (same shape
// NewOverlay accepts). Role overrides are empty until ReplaceRoleOverlays is called.
func NewRoleOverlay(tokens map[string]string) *RoleOverlay {
	return &RoleOverlay{defaultOverlay: NewOverlay(tokens)}
}

// NewRoleOverlayWithRules is NewRoleOverlay's richer form (see NewOverlayWithRules), for callers
// seeding the default rule set from the static SKYBRIDGE_PII_OVERLAY config (which supports partial
// masking, not just full-value replacement).
func NewRoleOverlayWithRules(rules map[string]OverlayRule) *RoleOverlay {
	return &RoleOverlay{defaultOverlay: NewOverlayWithRules(rules)}
}

// Replace atomically swaps the default (org-wide) rule set — same signature as *Overlay.Replace, so
// existing callers (the control-plane overlay poller) need no change beyond the parameter type.
func (r *RoleOverlay) Replace(tokens map[string]string) {
	r.defaultOverlay.Replace(tokens)
}

// ReplaceRoleOverlays atomically swaps the full set of per-role overrides. A role_id present in a
// previous call but absent from this one is dropped (falls back to the default overlay) — the
// control plane always sends the complete current set, never a delta.
func (r *RoleOverlay) ReplaceRoleOverlays(byRole map[string]map[string]string) {
	next := make(map[string]*Overlay, len(byRole))
	for roleID, tokens := range byRole {
		if roleID == "" {
			continue
		}
		next[roleID] = NewOverlay(tokens)
	}
	r.byRole.Store(&next)
}

// Enabled reports whether the default overlay has any rules — mirrors *Overlay.Enabled's meaning
// for the startup guardrail log (role overrides alone, with an empty default, only matter once a
// connection through that role is actually proxied).
func (r *RoleOverlay) Enabled() bool { return r.defaultOverlay.Enabled() }

// MaskRow implements Masker: selects the calling connection's resource_role_id override (via ctx)
// when one is configured, otherwise the default overlay.
func (r *RoleOverlay) MaskRow(ctx context.Context, cols []Column, row [][]byte) ([][]byte, error) {
	if roleID := ResourceRoleIDFromContext(ctx); roleID != "" {
		if m := r.byRole.Load(); m != nil {
			if ov, ok := (*m)[roleID]; ok {
				return ov.MaskRow(ctx, cols, row)
			}
		}
	}
	return r.defaultOverlay.MaskRow(ctx, cols, row)
}
