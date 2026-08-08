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
