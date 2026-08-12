package k8sexec

import (
	"context"
	"testing"

	"github.com/curlix-io/skybridge/internal/edge"
)

func TestRegistryHasKubectlTool(t *testing.T) {
	reg := edge.NewRegistry()
	Register(reg, Options{})
	if !reg.Has(ToolKubectl) {
		t.Fatal("missing kubectl_exec")
	}
}

func TestKubectlExecRejectsInvalidCommand(t *testing.T) {
	reg := edge.NewRegistry()
	Register(reg, Options{})
	res := reg.Dispatch(context.Background(), edge.ToolCall{
		Name:      ToolKubectl,
		Arguments: map[string]any{"command": "kubectl exec my-pod -- sh"},
	})
	if res["ok"] != false {
		t.Fatalf("expected ok=false: %+v", res)
	}
}

func TestKubectlExecRejectsMissingCommand(t *testing.T) {
	reg := edge.NewRegistry()
	Register(reg, Options{})
	res := reg.Dispatch(context.Background(), edge.ToolCall{
		Name:      ToolKubectl,
		Arguments: map[string]any{},
	})
	if res["ok"] != false {
		t.Fatalf("expected ok=false: %+v", res)
	}
}

func TestMaskSecretFieldsRedactsSecretData(t *testing.T) {
	payload := map[string]any{
		"kind": "Secret",
		"data": map[string]any{"password": "cGFzcw=="},
	}
	masked := maskSecretFields(payload).(map[string]any)
	data := masked["data"].(map[string]any)
	if data["password"] != redacted {
		t.Fatalf("expected password to be redacted, got %v", data["password"])
	}
}

func TestMaskSecretFieldsLeavesNonSecretsAlone(t *testing.T) {
	payload := map[string]any{
		"kind": "ConfigMap",
		"data": map[string]any{"config": "value"},
	}
	masked := maskSecretFields(payload).(map[string]any)
	data := masked["data"].(map[string]any)
	if data["config"] != "value" {
		t.Fatalf("expected ConfigMap data to be untouched, got %v", data["config"])
	}
}

func TestMaskSecretFieldsHandlesListOfSecrets(t *testing.T) {
	payload := map[string]any{
		"kind": "List",
		"items": []any{
			map[string]any{"kind": "Secret", "data": map[string]any{"k": "v"}},
			map[string]any{"kind": "ConfigMap", "data": map[string]any{"k": "v"}},
		},
	}
	masked := maskSecretFields(payload).(map[string]any)
	items := masked["items"].([]any)
	secretData := items[0].(map[string]any)["data"].(map[string]any)
	if secretData["k"] != redacted {
		t.Fatalf("expected Secret item data to be redacted, got %v", secretData["k"])
	}
	cmData := items[1].(map[string]any)["data"].(map[string]any)
	if cmData["k"] != "v" {
		t.Fatalf("expected ConfigMap item data untouched, got %v", cmData["k"])
	}
}

func TestWantsYAMLOutput(t *testing.T) {
	cases := []struct {
		name string
		argv []string
		want bool
	}{
		{"two-token -o yaml", []string{"get", "secret", "app-secret", "-o", "yaml"}, true},
		{"two-token --output yaml", []string{"get", "secret", "-o", "json"}, false},
		{"single-token -o=yaml", []string{"get", "secret", "-o=yaml"}, true},
		{"single-token --output=yaml", []string{"get", "secret", "--output=yaml"}, true},
		{"case insensitive YAML", []string{"get", "secret", "-o", "YAML"}, true},
		{"json requested, not yaml", []string{"get", "secret", "-o", "json"}, false},
		{"no output flag at all", []string{"get", "pods"}, false},
		{"-o with nothing after it", []string{"get", "secret", "-o"}, false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := wantsYAMLOutput(c.argv); got != c.want {
				t.Fatalf("wantsYAMLOutput(%v) = %v, want %v", c.argv, got, c.want)
			}
		})
	}
}

func TestMaskedYAMLOutputRedactsSecretData(t *testing.T) {
	yamlDoc := "apiVersion: v1\nkind: Secret\ndata:\n  password: cGFzcw==\n"
	got := maskedYAMLOutput(yamlDoc)
	out, ok := got.(map[string]any)
	if !ok {
		t.Fatalf("expected structured output, got %T", got)
	}
	data, ok := out["data"].(map[string]any)
	if !ok || data["password"] != redacted {
		t.Fatalf("expected password redacted, got %v", out["data"])
	}
}

func TestMaskedYAMLOutputReturnsNilForNonDocumentScalar(t *testing.T) {
	// A bare scalar ("just a string") is not what a real kubectl -o yaml document ever produces
	// (always a map or a list) — maskedYAMLOutput must fall back to nil (plain-text path) rather
	// than surfacing an unmasked bare scalar as "output".
	if got := maskedYAMLOutput("just a string, not a document"); got != nil {
		t.Fatalf("expected nil for a non-document scalar, got %v", got)
	}
}

func TestMaskedYAMLOutputReturnsNilForInvalidYAML(t *testing.T) {
	if got := maskedYAMLOutput("{not: valid: yaml: [["); got != nil {
		t.Fatalf("expected nil for invalid YAML, got %v", got)
	}
}
