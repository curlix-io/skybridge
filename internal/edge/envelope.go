// Package edge is the customer-side execution surface of the unified Skybridge edge binary. It
// receives single read-only tool calls dispatched from the SaaS control plane and runs them locally,
// so customer data (live AWS reads) is gathered inside the customer network and only results travel
// back. It is the Go counterpart of the Python connector's local tool execution path.
package edge

import (
	"encoding/json"
	"strings"
)

// Tool-call envelope. The SaaS side encodes a single tool call into the run "goal" string with a
// namespaced sentinel; the edge recognizes it and runs just that one tool (no LLM loop). This MUST
// stay byte-compatible with the control plane's tool-call envelope encoder/decoder — both ends agree
// on this exact shape.
const (
	envelopeKey     = "__curlix_mcp_tool__"
	envelopeVersion = 1
)

// ToolCall is a decoded single-tool request.
type ToolCall struct {
	Name      string
	Arguments map[string]any
}

// EncodeToolRequest mirrors the Python encoder: a JSON object carrying the sentinel/version, the
// tool name, and its arguments. Exposed mainly for round-trip tests and tooling.
func EncodeToolRequest(name string, arguments map[string]any) (string, error) {
	if arguments == nil {
		arguments = map[string]any{}
	}
	payload := map[string]any{
		envelopeKey: envelopeVersion,
		"name":      name,
		"arguments": arguments,
	}
	b, err := json.Marshal(payload)
	if err != nil {
		return "", err
	}
	return string(b), nil
}

// DecodeToolRequest returns the decoded ToolCall and true if goal is a valid tool-call envelope.
// It is intentionally defensive: any parse failure, missing/wrong sentinel, unsupported version, or
// empty name yields ok=false so a real natural-language goal is never mistaken for a tool call.
func DecodeToolRequest(goal string) (ToolCall, bool) {
	text := strings.TrimSpace(goal)
	if text == "" || !strings.HasPrefix(text, "{") || !strings.Contains(text, envelopeKey) {
		return ToolCall{}, false
	}
	var obj map[string]any
	if err := json.Unmarshal([]byte(text), &obj); err != nil {
		return ToolCall{}, false
	}
	// JSON numbers decode to float64; the sentinel version must equal envelopeVersion.
	v, ok := obj[envelopeKey].(float64)
	if !ok || int(v) != envelopeVersion {
		return ToolCall{}, false
	}
	name, ok := obj["name"].(string)
	if !ok {
		return ToolCall{}, false
	}
	name = strings.TrimSpace(name)
	if name == "" {
		return ToolCall{}, false
	}
	args, ok := obj["arguments"].(map[string]any)
	if !ok || args == nil {
		args = map[string]any{}
	}
	return ToolCall{Name: name, Arguments: args}, true
}
