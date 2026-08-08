package k8sapi

import (
	"encoding/json"
	"strings"
)

const redacted = "***redacted***"

// maskSecretJSON redacts Secret data/stringData fields in a JSON response body, the same field-mask
// rule as internal/edge/k8sexec's maskedJSONOutput/maskSecretFields (kept independent per-package,
// same local-copy rationale that package already documents). Returns raw unchanged when it is not
// JSON or masking would be a no-op.
func maskSecretJSON(raw []byte) []byte {
	trimmed := strings.TrimSpace(string(raw))
	if trimmed == "" || (trimmed[0] != '{' && trimmed[0] != '[') {
		return raw
	}
	var payload any
	if err := json.Unmarshal(raw, &payload); err != nil {
		return raw
	}
	masked := maskSecretFields(payload)
	out, err := json.Marshal(masked)
	if err != nil {
		return raw
	}
	return out
}

func maskSecretFields(payload any) any {
	switch v := payload.(type) {
	case []any:
		out := make([]any, len(v))
		for i, item := range v {
			out[i] = maskSecretFields(item)
		}
		return out
	case map[string]any:
		out := make(map[string]any, len(v))
		for k, val := range v {
			out[k] = val
		}
		if kind, _ := out["kind"].(string); strings.EqualFold(kind, "Secret") {
			for _, field := range []string{"data", "stringData"} {
				if m, ok := out[field].(map[string]any); ok {
					redactedMap := make(map[string]any, len(m))
					for k := range m {
						redactedMap[k] = redacted
					}
					out[field] = redactedMap
				}
			}
		}
		if items, ok := out["items"].([]any); ok {
			out["items"] = maskSecretFields(items)
		}
		return out
	default:
		return v
	}
}
