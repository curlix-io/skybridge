package k8stoken

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/curlix-io/skybridge/internal/edge"
)

func TestRegistryHasTokenRequestTool(t *testing.T) {
	reg := edge.NewRegistry()
	Register(reg, Options{})
	if !reg.Has(ToolKubernetesTokenRequest) {
		t.Fatal("missing k8s_token_request")
	}
}

func TestTokenRequestRejectsMissingNamespace(t *testing.T) {
	reg := edge.NewRegistry()
	Register(reg, Options{})
	res := reg.Dispatch(context.Background(), edge.ToolCall{
		Name:      ToolKubernetesTokenRequest,
		Arguments: map[string]any{"service_account": "reader"},
	})
	if res["ok"] != false {
		t.Fatalf("expected ok=false: %+v", res)
	}
}

func TestTokenRequestRejectsMissingServiceAccount(t *testing.T) {
	reg := edge.NewRegistry()
	Register(reg, Options{})
	res := reg.Dispatch(context.Background(), edge.ToolCall{
		Name:      ToolKubernetesTokenRequest,
		Arguments: map[string]any{"namespace": "default"},
	})
	if res["ok"] != false {
		t.Fatalf("expected ok=false: %+v", res)
	}
}

func TestClampDuration(t *testing.T) {
	cases := []struct {
		requested, def, max, want int64
	}{
		{0, 900, 3600, 900},     // unset -> default
		{-5, 900, 3600, 900},    // invalid -> default
		{100, 900, 3600, 100},   // within bounds -> unchanged
		{9000, 900, 3600, 3600}, // over max -> clamped
	}
	for _, c := range cases {
		got := clampDuration(c.requested, c.def, c.max)
		if got != c.want {
			t.Fatalf("clampDuration(%d, %d, %d) = %d, want %d", c.requested, c.def, c.max, got, c.want)
		}
	}
}

// fakeKubectl writes a small shell script standing in for the kubectl binary, so tests exercise
// argv construction and JSON parsing without a real cluster. `body` is the script's stdout.
func fakeKubectl(t *testing.T, body string, exitCode int) string {
	t.Helper()
	dir := t.TempDir()
	path := filepath.Join(dir, "kubectl")
	script := "#!/bin/sh\ncat <<'EOF'\n" + body + "\nEOF\nexit " + itoa(exitCode) + "\n"
	if err := os.WriteFile(path, []byte(script), 0o755); err != nil {
		t.Fatalf("write fake kubectl: %v", err)
	}
	return path
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	neg := n < 0
	if neg {
		n = -n
	}
	var buf []byte
	for n > 0 {
		buf = append([]byte{byte('0' + n%10)}, buf...)
		n /= 10
	}
	if neg {
		buf = append([]byte{'-'}, buf...)
	}
	return string(buf)
}

func TestTokenRequestParsesSuccessfulMint(t *testing.T) {
	bin := fakeKubectl(t, `{"status":{"token":"fake-token-abc","expirationTimestamp":"2026-01-01T00:00:00Z"}}`, 0)
	reg := edge.NewRegistry()
	Register(reg, Options{KubectlBin: bin})
	res := reg.Dispatch(context.Background(), edge.ToolCall{
		Name:      ToolKubernetesTokenRequest,
		Arguments: map[string]any{"namespace": "default", "service_account": "reader", "duration_seconds": 300},
	})
	if res["ok"] != true {
		t.Fatalf("expected ok=true: %+v", res)
	}
	if res["token"] != "fake-token-abc" {
		t.Fatalf("expected token to be parsed, got %+v", res)
	}
	if res["expiration"] != "2026-01-01T00:00:00Z" {
		t.Fatalf("expected expiration to be parsed, got %+v", res)
	}
}

func TestTokenRequestReportsKubectlFailure(t *testing.T) {
	bin := fakeKubectl(t, "", 1)
	reg := edge.NewRegistry()
	Register(reg, Options{KubectlBin: bin})
	res := reg.Dispatch(context.Background(), edge.ToolCall{
		Name:      ToolKubernetesTokenRequest,
		Arguments: map[string]any{"namespace": "default", "service_account": "reader"},
	})
	if res["ok"] != false {
		t.Fatalf("expected ok=false: %+v", res)
	}
}

func TestTokenRequestRejectsUnparsableOutput(t *testing.T) {
	bin := fakeKubectl(t, "not json", 0)
	reg := edge.NewRegistry()
	Register(reg, Options{KubectlBin: bin})
	res := reg.Dispatch(context.Background(), edge.ToolCall{
		Name:      ToolKubernetesTokenRequest,
		Arguments: map[string]any{"namespace": "default", "service_account": "reader"},
	})
	if res["ok"] != false {
		t.Fatalf("expected ok=false: %+v", res)
	}
}

// TestTokenRequestReportsTimeout exercises the timedOut branch of run: a fake kubectl that sleeps
// longer than the configured CLITimeout should be reported as a timed-out failure, not confused
// with a generic exec error.
func TestTokenRequestReportsTimeout(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "kubectl")
	script := "#!/bin/sh\nsleep 2\necho '{}'\n"
	if err := os.WriteFile(path, []byte(script), 0o755); err != nil {
		t.Fatalf("write fake kubectl: %v", err)
	}
	reg := edge.NewRegistry()
	Register(reg, Options{KubectlBin: path, CLITimeout: 50 * time.Millisecond})
	res := reg.Dispatch(context.Background(), edge.ToolCall{
		Name:      ToolKubernetesTokenRequest,
		Arguments: map[string]any{"namespace": "default", "service_account": "reader"},
	})
	if res["ok"] != false {
		t.Fatalf("expected ok=false: %+v", res)
	}
	if res["timed_out"] != true {
		t.Fatalf("expected timed_out=true: %+v", res)
	}
}

// TestTokenRequestUsesKubeconfigAndContext covers the argv-construction branches that prepend
// --kubeconfig/--context flags when Options set them, by having the fake kubectl echo its own
// argv back as JSON in the token field so the test can assert on it.
func TestTokenRequestUsesKubeconfigAndContext(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "kubectl")
	script := "#!/bin/sh\necho '{\"status\":{\"token\":\"'\"$*\"'\",\"expirationTimestamp\":\"x\"}}'\n"
	if err := os.WriteFile(path, []byte(script), 0o755); err != nil {
		t.Fatalf("write fake kubectl: %v", err)
	}
	reg := edge.NewRegistry()
	Register(reg, Options{KubectlBin: path, Kubeconfig: "/tmp/kc", Context: "my-ctx"})
	res := reg.Dispatch(context.Background(), edge.ToolCall{
		Name:      ToolKubernetesTokenRequest,
		Arguments: map[string]any{"namespace": "default", "service_account": "reader"},
	})
	if res["ok"] != true {
		t.Fatalf("expected ok=true: %+v", res)
	}
	token, _ := res["token"].(string)
	if !strings.Contains(token, "--kubeconfig /tmp/kc") || !strings.Contains(token, "--context my-ctx") {
		t.Fatalf("expected argv to include kubeconfig/context flags, got %q", token)
	}
}

func TestIntArg(t *testing.T) {
	cases := []struct {
		name string
		args map[string]any
		want int64
	}{
		{"missing key", map[string]any{}, 0},
		{"nil value", map[string]any{"duration_seconds": nil}, 0},
		{"int64", map[string]any{"duration_seconds": int64(42)}, 42},
		{"int", map[string]any{"duration_seconds": 7}, 7},
		{"float64", map[string]any{"duration_seconds": 3.0}, 3},
		{"unsupported type", map[string]any{"duration_seconds": "300"}, 0},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got := intArg(c.args, "duration_seconds")
			if got != c.want {
				t.Fatalf("intArg() = %d, want %d", got, c.want)
			}
		})
	}
}

func TestClip(t *testing.T) {
	cases := []struct {
		name string
		s    string
		max  int
		want string
	}{
		{"under limit unchanged", "short", 100, "short"},
		{"exact limit unchanged", "abcde", 5, "abcde"},
		{"over limit truncated", "abcdef", 5, "abcde"},
		{"zero max returns unchanged", "abcdef", 0, "abcdef"},
		{"negative max returns unchanged", "abcdef", -1, "abcdef"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got := clip(c.s, c.max)
			if got != c.want {
				t.Fatalf("clip(%q, %d) = %q, want %q", c.s, c.max, got, c.want)
			}
		})
	}
}
