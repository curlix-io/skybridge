package mask

import (
	"context"
	"testing"
)

func TestResourceRoleIDFromContextEmptyWhenNotAttached(t *testing.T) {
	if got := ResourceRoleIDFromContext(context.Background()); got != "" {
		t.Fatalf("expected empty role id, got %q", got)
	}
	if got := ResourceRoleIDFromContext(nil); got != "" { //nolint:staticcheck // explicit nil-ctx case
		t.Fatalf("expected empty role id for nil ctx, got %q", got)
	}
}

func TestWithResourceRoleIDRoundTrips(t *testing.T) {
	ctx := WithResourceRoleID(context.Background(), "role-1")
	if got := ResourceRoleIDFromContext(ctx); got != "role-1" {
		t.Fatalf("expected role-1, got %q", got)
	}
}

func TestWithResourceRoleIDEmptyIsNoop(t *testing.T) {
	ctx := WithResourceRoleID(context.Background(), "")
	if got := ResourceRoleIDFromContext(ctx); got != "" {
		t.Fatalf("expected empty role id, got %q", got)
	}
}

func TestRoleOverlayNoRoleIDUsesDefault(t *testing.T) {
	ov := NewRoleOverlay(map[string]string{"email": "[default]"})
	row := [][]byte{[]byte("a@b.com")}
	out, err := ov.MaskRow(context.Background(), cols("email"), row)
	if err != nil {
		t.Fatal(err)
	}
	if string(out[0]) != "[default]" {
		t.Fatalf("expected default rule applied, got %q", out[0])
	}
}

func TestRoleOverlayUnknownRoleIDFallsBackToDefault(t *testing.T) {
	ov := NewRoleOverlay(map[string]string{"email": "[default]"})
	ov.ReplaceRoleOverlays(map[string]map[string]string{"role-1": {"email": "[role-1]"}})
	ctx := WithResourceRoleID(context.Background(), "role-unknown")
	out, err := ov.MaskRow(ctx, cols("email"), [][]byte{[]byte("a@b.com")})
	if err != nil {
		t.Fatal(err)
	}
	if string(out[0]) != "[default]" {
		t.Fatalf("unknown role id should fall back to default, got %q", out[0])
	}
}

func TestRoleOverlayKnownRoleIDUsesItsOwnRules(t *testing.T) {
	ov := NewRoleOverlay(map[string]string{"email": "[default]"})
	ov.ReplaceRoleOverlays(map[string]map[string]string{
		"role-1": {"email": "[role-1]"},
		"role-2": {"email": "[role-2]"},
	})

	out1, _ := ov.MaskRow(WithResourceRoleID(context.Background(), "role-1"), cols("email"), [][]byte{[]byte("a@b.com")})
	if string(out1[0]) != "[role-1]" {
		t.Fatalf("role-1 connection should use its own rule, got %q", out1[0])
	}

	out2, _ := ov.MaskRow(WithResourceRoleID(context.Background(), "role-2"), cols("email"), [][]byte{[]byte("a@b.com")})
	if string(out2[0]) != "[role-2]" {
		t.Fatalf("role-2 connection should use its own rule, got %q", out2[0])
	}

	// A connection through neither role still gets the org default, unaffected by either override.
	outDefault, _ := ov.MaskRow(context.Background(), cols("email"), [][]byte{[]byte("a@b.com")})
	if string(outDefault[0]) != "[default]" {
		t.Fatalf("no-role connection should be unaffected by role overrides, got %q", outDefault[0])
	}
}

func TestRoleOverlayReplaceRoleOverlaysDropsRemovedRoles(t *testing.T) {
	ov := NewRoleOverlay(map[string]string{"email": "[default]"})
	ov.ReplaceRoleOverlays(map[string]map[string]string{"role-1": {"email": "[role-1]"}})
	ctx := WithResourceRoleID(context.Background(), "role-1")
	out, _ := ov.MaskRow(ctx, cols("email"), [][]byte{[]byte("a@b.com")})
	if string(out[0]) != "[role-1]" {
		t.Fatalf("expected role-1 override before replacement, got %q", out[0])
	}

	// A later poll response with role-1 absent must drop its override, falling back to default —
	// the control plane always sends the complete current set, never a delta.
	ov.ReplaceRoleOverlays(map[string]map[string]string{})
	out, _ = ov.MaskRow(ctx, cols("email"), [][]byte{[]byte("a@b.com")})
	if string(out[0]) != "[default]" {
		t.Fatalf("expected fallback to default after role-1 dropped, got %q", out[0])
	}
}

func TestRoleOverlayReplaceUpdatesDefaultOnly(t *testing.T) {
	ov := NewRoleOverlay(map[string]string{"email": "[default-1]"})
	ov.ReplaceRoleOverlays(map[string]map[string]string{"role-1": {"email": "[role-1]"}})

	ov.Replace(map[string]string{"email": "[default-2]"})

	outDefault, _ := ov.MaskRow(context.Background(), cols("email"), [][]byte{[]byte("a@b.com")})
	if string(outDefault[0]) != "[default-2]" {
		t.Fatalf("expected updated default rule, got %q", outDefault[0])
	}
	outRole, _ := ov.MaskRow(WithResourceRoleID(context.Background(), "role-1"), cols("email"), [][]byte{[]byte("a@b.com")})
	if string(outRole[0]) != "[role-1]" {
		t.Fatalf("role override must survive a default-only Replace, got %q", outRole[0])
	}
}

func TestRoleOverlayIgnoresEmptyRoleIDKey(t *testing.T) {
	ov := NewRoleOverlay(map[string]string{"email": "[default]"})
	// A malformed/empty key in the poll response must never be stored (would otherwise be
	// unreachable anyway, since ResourceRoleIDFromContext/WithResourceRoleID never produce "").
	ov.ReplaceRoleOverlays(map[string]map[string]string{"": {"email": "[should-not-apply]"}})
	out, _ := ov.MaskRow(context.Background(), cols("email"), [][]byte{[]byte("a@b.com")})
	if string(out[0]) != "[default]" {
		t.Fatalf("expected default rule unaffected by an empty-key entry, got %q", out[0])
	}
}

func TestRoleOverlayEnabledReflectsDefaultOverlay(t *testing.T) {
	ov := NewRoleOverlay(nil)
	if ov.Enabled() {
		t.Fatal("expected disabled with no default rules")
	}
	ov.Replace(map[string]string{"email": "[default]"})
	if !ov.Enabled() {
		t.Fatal("expected enabled once default rules are set")
	}
}

func TestNewRoleOverlayWithRulesSupportsPartialMask(t *testing.T) {
	ov := NewRoleOverlayWithRules(map[string]OverlayRule{"credit_card": {Partial: true}})
	out, err := ov.MaskRow(context.Background(), cols("credit_card"), [][]byte{[]byte("4111111111111234")})
	if err != nil {
		t.Fatal(err)
	}
	if string(out[0]) == "4111111111111234" {
		t.Fatal("expected partial masking to change the value")
	}
}
