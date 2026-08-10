package k8sapi

import (
	"encoding/json"
	"testing"
)

func TestMaskSecretJSONRedactsSecretData(t *testing.T) {
	raw, _ := json.Marshal(map[string]any{
		"kind": "Secret",
		"data": map[string]any{"password": "cGFzcw=="},
	})
	var out map[string]any
	if err := json.Unmarshal(maskSecretJSON(raw), &out); err != nil {
		t.Fatalf("unmarshal masked output: %v", err)
	}
	data := out["data"].(map[string]any)
	if data["password"] != redacted {
		t.Fatalf("expected password redacted, got %v", data["password"])
	}
}

func TestMaskSecretJSONLeavesNonSecretsAlone(t *testing.T) {
	raw, _ := json.Marshal(map[string]any{
		"kind": "ConfigMap",
		"data": map[string]any{"config": "value"},
	})
	var out map[string]any
	if err := json.Unmarshal(maskSecretJSON(raw), &out); err != nil {
		t.Fatalf("unmarshal masked output: %v", err)
	}
	data := out["data"].(map[string]any)
	if data["config"] != "value" {
		t.Fatalf("expected ConfigMap data untouched, got %v", data["config"])
	}
}

func TestMaskSecretJSONNonJSONPassthrough(t *testing.T) {
	raw := []byte("not json")
	if got := maskSecretJSON(raw); string(got) != string(raw) {
		t.Fatalf("expected non-JSON passthrough unchanged, got %q", got)
	}
}

func TestMaskSecretJSONEmptyPassthrough(t *testing.T) {
	raw := []byte("   ")
	if got := maskSecretJSON(raw); string(got) != string(raw) {
		t.Fatalf("expected empty/whitespace passthrough unchanged, got %q", got)
	}
}

func TestMaskSecretJSONMalformedJSONPassthrough(t *testing.T) {
	// Starts with '{' so it passes the cheap prefix check, but isn't valid JSON — must fall
	// through unchanged rather than corrupt it (fallthrough-never-corrupt contract).
	raw := []byte("{not valid json")
	if got := maskSecretJSON(raw); string(got) != string(raw) {
		t.Fatalf("expected malformed JSON passthrough unchanged, got %q", got)
	}
}

func TestMaskSecretFieldsScalarPassthrough(t *testing.T) {
	// maskSecretFields' default branch handles scalar JSON values (string/number/bool/nil)
	// encountered while walking a document — must return them unchanged.
	for _, v := range []any{"plain string", 42.0, true, nil} {
		if got := maskSecretFields(v); got != v {
			t.Fatalf("expected scalar %v passthrough unchanged, got %v", v, got)
		}
	}
}

func TestMaskSecretJSONListOfSecrets(t *testing.T) {
	raw, _ := json.Marshal(map[string]any{
		"kind": "List",
		"items": []any{
			map[string]any{"kind": "Secret", "data": map[string]any{"k": "v"}},
			map[string]any{"kind": "ConfigMap", "data": map[string]any{"k": "v"}},
		},
	})
	var out map[string]any
	if err := json.Unmarshal(maskSecretJSON(raw), &out); err != nil {
		t.Fatalf("unmarshal masked output: %v", err)
	}
	items := out["items"].([]any)
	secretData := items[0].(map[string]any)["data"].(map[string]any)
	if secretData["k"] != redacted {
		t.Fatalf("expected Secret item data redacted, got %v", secretData["k"])
	}
	cmData := items[1].(map[string]any)["data"].(map[string]any)
	if cmData["k"] != "v" {
		t.Fatalf("expected ConfigMap item data untouched, got %v", cmData["k"])
	}
}
