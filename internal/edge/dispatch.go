package edge

import (
	"context"
	"fmt"
	"sort"
)

// Result is a JSON-serializable tool result. It mirrors the Python tool convention: every result
// carries at least {"ok": bool, "tool": name}, plus tool-specific fields. The SaaS side wraps this
// into a ToolResult agent event and applies PII redaction before it reaches the model/UI.
type Result map[string]any

// Handler executes one read-only tool locally and returns its Result. A returned error is for
// transport/internal failures; tool-level failures should be reported as a Result with ok=false so
// the SaaS side still gets a structured answer.
type Handler func(ctx context.Context, args map[string]any) (Result, error)

// Registry maps tool names to local handlers. Only tools that genuinely need to run at the customer
// edge (live AWS reads) are registered here; everything else stays SaaS-side and is never dispatched
// to the edge.
type Registry struct {
	handlers map[string]Handler
}

// NewRegistry returns an empty registry.
func NewRegistry() *Registry {
	return &Registry{handlers: map[string]Handler{}}
}

// Register adds (or replaces) a handler for name. It panics on an empty name or nil handler since
// that is always a programming error at wiring time.
func (r *Registry) Register(name string, h Handler) {
	if name == "" || h == nil {
		panic("edge: Register requires a non-empty name and non-nil handler")
	}
	r.handlers[name] = h
}

// Has reports whether a tool is handled at the edge.
func (r *Registry) Has(name string) bool {
	_, ok := r.handlers[name]
	return ok
}

// Names returns the registered tool names, sorted (stable for logging/tests).
func (r *Registry) Names() []string {
	out := make([]string, 0, len(r.handlers))
	for n := range r.handlers {
		out = append(out, n)
	}
	sort.Strings(out)
	return out
}

// Dispatch runs a decoded tool call. Unknown tools return an ok=false Result (not an error) so the
// caller can forward a structured rejection up the tunnel; a non-nil error is reserved for handler
// transport failures. A handler that returns an error is converted into an ok=false Result too, so
// the edge never drops a dispatched call silently.
func (r *Registry) Dispatch(ctx context.Context, call ToolCall) Result {
	h, ok := r.handlers[call.Name]
	if !ok {
		return ErrorResult(call.Name, fmt.Sprintf("tool %q is not handled at the edge", call.Name))
	}
	res, err := h(ctx, call.Arguments)
	if err != nil {
		return ErrorResult(call.Name, err.Error())
	}
	if res == nil {
		res = Result{}
	}
	if _, present := res["tool"]; !present {
		res["tool"] = call.Name
	}
	if _, present := res["ok"]; !present {
		res["ok"] = true
	}
	return res
}

// ErrorResult builds a uniform ok=false result for a tool.
func ErrorResult(tool, msg string) Result {
	return Result{"ok": false, "tool": tool, "error": msg}
}
