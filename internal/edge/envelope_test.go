package edge

import "testing"

func TestDecodeToolRequestValid(t *testing.T) {
	goal := `{"__curlix_mcp_tool__":1,"name":"cloudwatch_metrics","arguments":{"ecs_cluster":"c","ecs_service":"s"}}`
	tc, ok := DecodeToolRequest(goal)
	if !ok {
		t.Fatal("expected valid envelope")
	}
	if tc.Name != "cloudwatch_metrics" {
		t.Fatalf("name = %q", tc.Name)
	}
	if tc.Arguments["ecs_cluster"] != "c" || tc.Arguments["ecs_service"] != "s" {
		t.Fatalf("args = %+v", tc.Arguments)
	}
}

func TestDecodeToolRequestRejects(t *testing.T) {
	cases := map[string]string{
		"plain goal":       "why is checkout slow?",
		"empty":            "",
		"no sentinel":      `{"name":"x","arguments":{}}`,
		"wrong version":    `{"__curlix_mcp_tool__":2,"name":"x"}`,
		"empty name":       `{"__curlix_mcp_tool__":1,"name":"   "}`,
		"name not string":  `{"__curlix_mcp_tool__":1,"name":5}`,
		"not an object":    `["__curlix_mcp_tool__"]`,
		"malformed json":   `{"__curlix_mcp_tool__":1,`,
		"sentinel as text": "the __curlix_mcp_tool__ is great",
		"missing name":     `{"__curlix_mcp_tool__":1,"arguments":{}}`,
	}
	for name, goal := range cases {
		if _, ok := DecodeToolRequest(goal); ok {
			t.Errorf("%s: expected reject, got accept", name)
		}
	}
}

func TestDecodeToolRequestMissingArgsDefaultsEmpty(t *testing.T) {
	tc, ok := DecodeToolRequest(`{"__curlix_mcp_tool__":1,"name":"list_incidents"}`)
	if !ok {
		t.Fatal("expected valid")
	}
	if tc.Arguments == nil || len(tc.Arguments) != 0 {
		t.Fatalf("arguments should default to empty map, got %+v", tc.Arguments)
	}
}

func TestEncodeDecodeRoundTrip(t *testing.T) {
	s, err := EncodeToolRequest("aws_readonly_cli", map[string]any{"command": "aws ec2 describe-instances"})
	if err != nil {
		t.Fatal(err)
	}
	tc, ok := DecodeToolRequest(s)
	if !ok {
		t.Fatal("round-trip decode failed")
	}
	if tc.Name != "aws_readonly_cli" || tc.Arguments["command"] != "aws ec2 describe-instances" {
		t.Fatalf("round-trip mismatch: %+v", tc)
	}
}

func TestEncodeNilArgs(t *testing.T) {
	s, err := EncodeToolRequest("summary", nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := DecodeToolRequest(s); !ok {
		t.Fatal("encoded nil-arg envelope should decode")
	}
}
