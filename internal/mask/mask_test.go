package mask

import (
	"context"
	"errors"
	"testing"
)

func cols(names ...string) []Column {
	out := make([]Column, len(names))
	for i, n := range names {
		out[i] = Column{Name: n, Text: true, FreeText: true}
	}
	return out
}

func TestOverlayRedactsConfiguredColumns(t *testing.T) {
	o := NewOverlay(map[string]string{"Email": "[redacted]"})
	if !o.Enabled() {
		t.Fatal("overlay should be enabled")
	}
	row := [][]byte{[]byte("7"), []byte("a@b.com")}
	out, err := o.MaskRow(context.Background(), cols("id", "email"), row)
	if err != nil {
		t.Fatal(err)
	}
	if string(out[0]) != "7" {
		t.Fatal("id should be unchanged")
	}
	if string(out[1]) != "[redacted]" {
		t.Fatalf("email should be redacted, got %q", out[1])
	}
}

func TestOverlayEmptyIsNoop(t *testing.T) {
	o := NewOverlay(nil)
	if o.Enabled() {
		t.Fatal("empty overlay should be disabled")
	}
	row := [][]byte{[]byte("a@b.com")}
	out, _ := o.MaskRow(context.Background(), cols("email"), row)
	if string(out[0]) != "a@b.com" {
		t.Fatal("empty overlay must not change values")
	}
}

func TestOverlaySkipsNullAndBinary(t *testing.T) {
	o := NewOverlay(map[string]string{"email": "x"})
	c := []Column{{Name: "email", Text: false}} // binary column
	row := [][]byte{[]byte("a@b.com")}
	out, _ := o.MaskRow(context.Background(), c, row)
	if string(out[0]) != "a@b.com" {
		t.Fatal("binary-format values must pass through")
	}
}

func TestChainAppliesInOrder(t *testing.T) {
	first := NewOverlay(map[string]string{"a": "1"})
	second := NewOverlay(map[string]string{"b": "2"})
	chain := NewChain(first, nil, second) // nil masker is skipped
	row := [][]byte{[]byte("x"), []byte("y")}
	out, err := chain.MaskRow(context.Background(), cols("a", "b"), row)
	if err != nil {
		t.Fatal(err)
	}
	if string(out[0]) != "1" || string(out[1]) != "2" {
		t.Fatalf("chain did not apply both maskers: %q %q", out[0], out[1])
	}
}

func TestOverlayReplaceHotSwap(t *testing.T) {
	o := NewOverlay(nil)
	if o.Enabled() {
		t.Fatal("overlay should start disabled")
	}
	// Swap in rules at runtime (as the control-plane poller would).
	o.Replace(map[string]string{"Email": "[email]"})
	if !o.Enabled() {
		t.Fatal("overlay should be enabled after Replace")
	}
	out, _ := o.MaskRow(context.Background(), cols("id", "email"), [][]byte{[]byte("7"), []byte("a@b.com")})
	if string(out[1]) != "[email]" {
		t.Fatalf("expected hot-swapped rule to apply, got %q", out[1])
	}
	// Swap to empty → back to no-op.
	o.Replace(nil)
	if o.Enabled() {
		t.Fatal("overlay should be disabled after empty Replace")
	}
	out, _ = o.MaskRow(context.Background(), cols("email"), [][]byte{[]byte("a@b.com")})
	if string(out[0]) != "a@b.com" {
		t.Fatal("empty overlay must not change values after swap")
	}
}

// errMasker always fails MaskRow, to exercise Chain.MaskRow's error-short-circuit branch.
type errMasker struct{ err error }

func (e errMasker) MaskRow(_ context.Context, _ []Column, row [][]byte) ([][]byte, error) {
	return row, e.err
}

func TestChainShortCircuitsOnError(t *testing.T) {
	boom := errors.New("boom")
	first := errMasker{err: boom}
	second := NewOverlay(map[string]string{"a": "should-not-run"})
	chain := NewChain(first, second)
	row := [][]byte{[]byte("x")}
	out, err := chain.MaskRow(context.Background(), cols("a"), row)
	if !errors.Is(err, boom) {
		t.Fatalf("expected chain to surface the first masker's error, got %v", err)
	}
	if string(out[0]) != "x" {
		t.Fatalf("expected row from the failing masker to be returned unchanged, got %q", out[0])
	}
}

func TestOverlayNormalizeRulesSkipsBlankKeys(t *testing.T) {
	o := NewOverlay(map[string]string{"  ": "ignored", "Email": "[redacted]"})
	row := [][]byte{[]byte("a@b.com")}
	out, _ := o.MaskRow(context.Background(), cols("email"), row)
	if string(out[0]) != "[redacted]" {
		t.Fatalf("expected blank-key rule to be dropped and real rule to still apply, got %q", out[0])
	}
}

func TestOverlayCurrentNilPointerFallsBackToNil(t *testing.T) {
	// current()'s nil-pointer fallback is only reachable if the atomic.Pointer was never stored —
	// NewOverlay always stores one, so use a zero-value Overlay to exercise the fallback directly.
	var o Overlay
	if got := o.current(); got != nil {
		t.Fatalf("expected nil fallback from an unset Overlay, got %v", got)
	}
	if o.Enabled() {
		t.Fatal("expected an unset Overlay to report Enabled() false")
	}
}

func TestNoop(t *testing.T) {
	row := [][]byte{[]byte("a@b.com")}
	out, err := Noop{}.MaskRow(context.Background(), cols("email"), row)
	if err != nil || string(out[0]) != "a@b.com" {
		t.Fatal("noop must return rows unchanged")
	}
}
