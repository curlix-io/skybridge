package k8sexec

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/curlix-io/skybridge/internal/edge"
)

// writeFakeKubectl drops an executable shell script at dir/kubectl that behaves according to the
// scenarios below, keyed off a marker token present anywhere in argv. Using a real subprocess (as
// opposed to mocking exec.Command) exercises Executor.run's actual exec.CommandContext plumbing —
// stdout/stderr capture, exit codes, and the timeout path.
func writeFakeKubectl(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	path := filepath.Join(dir, "kubectl")
	script := `#!/bin/sh
case "$*" in
  *secretout*)
    echo '{"kind":"Secret","data":{"password":"cGFzcw=="},"stringData":{"note":"hi"}}'
    ;;
  *secretyaml*)
    printf 'apiVersion: v1\nkind: Secret\ndata:\n  password: cGFzcw==\nstringData:\n  note: hi\n'
    ;;
  *plaintable*)
    printf 'NAME    READY   STATUS    RESTARTS   AGE\nmypod   1/1     Running   0          5d\n'
    ;;
  *plainjson*)
    echo '{"kind":"ConfigMap","data":{"k":"v"}}'
    ;;
  *badjson*)
    echo 'not-json-output'
    ;;
  *failcmd*)
    echo "boom" 1>&2
    exit 3
    ;;
  *sleepcmd*)
    sleep 5
    ;;
  *checkflags*)
    echo "ARGS:$*"
    ;;
  *)
    echo "hello"
    ;;
esac
`
	if err := os.WriteFile(path, []byte(script), 0o755); err != nil {
		t.Fatalf("write fake kubectl: %v", err)
	}
	return path
}

func runKubectl(t *testing.T, opts Options, command string) edge.Result {
	t.Helper()
	reg := edge.NewRegistry()
	Register(reg, opts)
	return reg.Dispatch(context.Background(), edge.ToolCall{
		Name:      ToolKubectl,
		Arguments: map[string]any{"command": command},
	})
}

func TestKubectlExecMasksSecretJSONOutput(t *testing.T) {
	bin := writeFakeKubectl(t)
	res := runKubectl(t, Options{KubectlBin: bin}, "kubectl get secretout")
	if res["ok"] != true {
		t.Fatalf("expected ok=true: %+v", res)
	}
	out, ok := res["output"].(map[string]any)
	if !ok {
		t.Fatalf("expected structured output, got %T: %v", res["output"], res["output"])
	}
	data, ok := out["data"].(map[string]any)
	if !ok || data["password"] != redacted {
		t.Fatalf("expected password redacted, got %v", out["data"])
	}
	stringData, ok := out["stringData"].(map[string]any)
	if !ok || stringData["note"] != redacted {
		t.Fatalf("expected stringData redacted, got %v", out["stringData"])
	}
}

// TestKubectlExecMasksSecretYAMLOutput is the regression test for the "-o yaml bypasses secret
// redaction" gap: before wantsYAMLOutput/maskedYAMLOutput existed, the exact same Secret resource
// that got its data/stringData redacted under -o json came back with raw, unredacted base64 secret
// material under -o yaml — the same "read-only" broker, one output flag away from a full bypass.
func TestKubectlExecMasksSecretYAMLOutput(t *testing.T) {
	bin := writeFakeKubectl(t)
	res := runKubectl(t, Options{KubectlBin: bin}, "kubectl get secretyaml -o yaml")
	if res["ok"] != true {
		t.Fatalf("expected ok=true: %+v", res)
	}
	out, ok := res["output"].(map[string]any)
	if !ok {
		t.Fatalf("expected structured output, got %T: %v", res["output"], res["output"])
	}
	data, ok := out["data"].(map[string]any)
	if !ok || data["password"] != redacted {
		t.Fatalf("expected password redacted, got %v", out["data"])
	}
	stringData, ok := out["stringData"].(map[string]any)
	if !ok || stringData["note"] != redacted {
		t.Fatalf("expected stringData redacted, got %v", out["stringData"])
	}
}

// TestKubectlExecMasksSecretYAMLOutputShorthandFlag confirms the "-o=yaml" and "--output=yaml"
// single-token spellings are recognized too, not just the two-token "-o yaml" form.
func TestKubectlExecMasksSecretYAMLOutputShorthandFlag(t *testing.T) {
	bin := writeFakeKubectl(t)
	res := runKubectl(t, Options{KubectlBin: bin}, "kubectl get secretyaml --output=yaml")
	if res["ok"] != true {
		t.Fatalf("expected ok=true: %+v", res)
	}
	out, ok := res["output"].(map[string]any)
	if !ok {
		t.Fatalf("expected structured output, got %T: %v", res["output"], res["output"])
	}
	if data, ok := out["data"].(map[string]any); !ok || data["password"] != redacted {
		t.Fatalf("expected password redacted, got %v", out["data"])
	}
}

// TestKubectlExecPlainTableOutputNotMisparsedAsYAML confirms kubectl's default table format (no -o
// flag at all) is never fed to the YAML masker — wantsYAMLOutput must gate strictly on the command
// actually requesting YAML, not on sniffing stdout content, since arbitrary text can coincidentally
// look YAML-ish.
func TestKubectlExecPlainTableOutputNotMisparsedAsYAML(t *testing.T) {
	bin := writeFakeKubectl(t)
	res := runKubectl(t, Options{KubectlBin: bin}, "kubectl get plaintable")
	if res["ok"] != true {
		t.Fatalf("expected ok=true: %+v", res)
	}
	out, ok := res["output"].(string)
	if !ok {
		t.Fatalf("expected raw table text to pass through as a string, got %T: %v", res["output"], res["output"])
	}
	if !strings.Contains(out, "mypod") {
		t.Fatalf("expected table output preserved, got %q", out)
	}
}

func TestKubectlExecLeavesPlainJSONOutputUnmasked(t *testing.T) {
	bin := writeFakeKubectl(t)
	res := runKubectl(t, Options{KubectlBin: bin}, "kubectl get plainjson")
	if res["ok"] != true {
		t.Fatalf("expected ok=true: %+v", res)
	}
	out, ok := res["output"].(map[string]any)
	if !ok {
		t.Fatalf("expected structured output, got %T", res["output"])
	}
	data := out["data"].(map[string]any)
	if data["k"] != "v" {
		t.Fatalf("expected ConfigMap data untouched, got %v", data["k"])
	}
}

func TestKubectlExecFallsBackToRawOutputOnNonJSON(t *testing.T) {
	bin := writeFakeKubectl(t)
	res := runKubectl(t, Options{KubectlBin: bin}, "kubectl get badjson")
	if res["ok"] != true {
		t.Fatalf("expected ok=true: %+v", res)
	}
	out, ok := res["output"].(string)
	if !ok {
		t.Fatalf("expected string output, got %T", res["output"])
	}
	if out == "" {
		t.Fatal("expected non-empty raw output")
	}
}

func TestKubectlExecReportsNonZeroExit(t *testing.T) {
	bin := writeFakeKubectl(t)
	res := runKubectl(t, Options{KubectlBin: bin}, "kubectl get failcmd")
	if res["ok"] != false {
		t.Fatalf("expected ok=false: %+v", res)
	}
	if res["exit_code"] != 3 {
		t.Fatalf("expected exit_code=3, got %v", res["exit_code"])
	}
	stderrOut, _ := res["stderr"].(string)
	if stderrOut == "" {
		t.Fatal("expected stderr captured")
	}
	if _, hasOutput := res["output"]; hasOutput {
		t.Fatalf("expected no output key on failure, got %+v", res)
	}
}

func TestKubectlExecTimesOut(t *testing.T) {
	bin := writeFakeKubectl(t)
	res := runKubectl(t, Options{KubectlBin: bin, CLITimeout: 100 * time.Millisecond}, "kubectl get sleepcmd")
	if res["ok"] != false {
		t.Fatalf("expected ok=false on timeout: %+v", res)
	}
	if res["timed_out"] != true {
		t.Fatalf("expected timed_out=true: %+v", res)
	}
}

func TestKubectlExecPrependsKubeconfigAndContextFlags(t *testing.T) {
	bin := writeFakeKubectl(t)
	res := runKubectl(t, Options{KubectlBin: bin, Kubeconfig: "/tmp/kc", Context: "my-ctx"}, "kubectl get checkflags")
	if res["ok"] != true {
		t.Fatalf("expected ok=true: %+v", res)
	}
	out, _ := res["output"].(string)
	if !contains(out, "--kubeconfig /tmp/kc") || !contains(out, "--context my-ctx") {
		t.Fatalf("expected kubeconfig/context flags prepended, got %q", out)
	}
}

func TestKubectlExecRejectsUnresolvableBinary(t *testing.T) {
	res := runKubectl(t, Options{KubectlBin: filepath.Join(t.TempDir(), "does-not-exist")}, "kubectl get pods")
	if res["ok"] != false {
		t.Fatalf("expected ok=false when binary missing: %+v", res)
	}
	errMsg, _ := res["error"].(string)
	if errMsg == "" {
		t.Fatal("expected an error message when exec fails outright")
	}
}

func TestClipTruncatesLongStrings(t *testing.T) {
	if got := clip("hello world", 5); got != "hello" {
		t.Fatalf("expected clipped string, got %q", got)
	}
	if got := clip("short", 0); got != "short" {
		t.Fatalf("expected clip with max<=0 to be a no-op, got %q", got)
	}
	if got := clip("short", 100); got != "short" {
		t.Fatalf("expected clip with max>len to be a no-op, got %q", got)
	}
}

func contains(s, sub string) bool {
	return len(s) >= len(sub) && (func() bool {
		for i := 0; i+len(sub) <= len(s); i++ {
			if s[i:i+len(sub)] == sub {
				return true
			}
		}
		return false
	})()
}
