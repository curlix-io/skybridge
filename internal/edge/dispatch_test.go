package edge

import (
	"context"
	"errors"
	"testing"
)

func TestDispatchKnownTool(t *testing.T) {
	r := NewRegistry()
	r.Register("echo", func(_ context.Context, args map[string]any) (Result, error) {
		return Result{"ok": true, "tool": "echo", "got": args["x"]}, nil
	})
	res := r.Dispatch(context.Background(), ToolCall{Name: "echo", Arguments: map[string]any{"x": 42}})
	if res["ok"] != true || res["got"] != 42 {
		t.Fatalf("unexpected result: %+v", res)
	}
}

func TestDispatchUnknownTool(t *testing.T) {
	r := NewRegistry()
	res := r.Dispatch(context.Background(), ToolCall{Name: "inventory_graph_query"})
	if res["ok"] != false {
		t.Fatalf("unknown tool should be ok=false: %+v", res)
	}
	if res["tool"] != "inventory_graph_query" {
		t.Fatalf("tool name not echoed: %+v", res)
	}
}

func TestDispatchHandlerErrorBecomesResult(t *testing.T) {
	r := NewRegistry()
	r.Register("boom", func(_ context.Context, _ map[string]any) (Result, error) {
		return nil, errors.New("kaboom")
	})
	res := r.Dispatch(context.Background(), ToolCall{Name: "boom"})
	if res["ok"] != false || res["error"] != "kaboom" {
		t.Fatalf("handler error not surfaced: %+v", res)
	}
}

func TestDispatchFillsDefaults(t *testing.T) {
	r := NewRegistry()
	r.Register("bare", func(_ context.Context, _ map[string]any) (Result, error) {
		return Result{"value": 1}, nil // no ok/tool keys
	})
	res := r.Dispatch(context.Background(), ToolCall{Name: "bare"})
	if res["ok"] != true || res["tool"] != "bare" || res["value"] != 1 {
		t.Fatalf("defaults not filled: %+v", res)
	}
}

func TestRegistryHasAndNames(t *testing.T) {
	r := NewRegistry()
	r.Register("b", func(_ context.Context, _ map[string]any) (Result, error) { return nil, nil })
	r.Register("a", func(_ context.Context, _ map[string]any) (Result, error) { return nil, nil })
	if !r.Has("a") || !r.Has("b") || r.Has("c") {
		t.Fatal("Has wrong")
	}
	names := r.Names()
	if len(names) != 2 || names[0] != "a" || names[1] != "b" {
		t.Fatalf("Names not sorted: %v", names)
	}
}

func TestRegisterPanicsOnBadInput(t *testing.T) {
	r := NewRegistry()
	defer func() {
		if recover() == nil {
			t.Fatal("expected panic on nil handler")
		}
	}()
	r.Register("x", nil)
}
