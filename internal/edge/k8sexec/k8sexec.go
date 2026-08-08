package k8sexec

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"os/exec"
	"strings"
	"time"

	"github.com/curlix-io/skybridge/internal/edge"
)

// ToolKubectl is the SaaS-side tool name this package handles — MUST match the backend's
// edge_tool_names() (backend/src/curlix/ai_agent/tool_executor.py).
const ToolKubectl = "kubectl_exec"

// Options configures the edge kubectl executor.
type Options struct {
	Kubeconfig string        // path to a kubeconfig file (default: kubectl's own default resolution)
	Context    string        // kubeconfig context to use (optional)
	KubectlBin string        // path to the kubectl binary (default "kubectl")
	CLITimeout time.Duration // per-invocation timeout (default 30s)
	MaxStdout  int           // stdout cap in bytes (default 200000 — cluster JSON can be large)
	MaxStderr  int           // stderr cap in bytes (default 4000)
}

func (o Options) withDefaults() Options {
	if o.KubectlBin == "" {
		o.KubectlBin = "kubectl"
	}
	if o.CLITimeout <= 0 {
		o.CLITimeout = 30 * time.Second
	}
	if o.MaxStdout <= 0 {
		o.MaxStdout = 200_000
	}
	if o.MaxStderr <= 0 {
		o.MaxStderr = 4000
	}
	return o
}

// Executor runs the edge kubectl tool with a fixed set of options.
type Executor struct {
	opts Options
}

// New builds an Executor with defaults applied.
func New(opts Options) Executor {
	return Executor{opts: opts.withDefaults()}
}

// Register wires kubectl_exec into the edge registry.
func Register(reg *edge.Registry, opts Options) {
	e := New(opts)
	reg.Register(ToolKubectl, e.run)
}

func (e Executor) run(ctx context.Context, args map[string]any) (edge.Result, error) {
	command := strArg(args, "command")

	allowed, reason, parsed := ValidateKubectlCommand(command)
	if !allowed {
		return edge.Result{"ok": false, "tool": ToolKubectl, "command": clip(command, 500), "error": "Command rejected by policy: " + reason}, nil
	}

	argv, err := shlexSplit(strings.TrimSpace(command))
	if err != nil || len(argv) < 2 || argv[0] != "kubectl" {
		return edge.Result{"ok": false, "tool": ToolKubectl, "command": clip(command, 500), "error": "could not parse command"}, nil
	}
	kubectlArgs := argv[1:]
	if e.opts.Kubeconfig != "" {
		kubectlArgs = append([]string{"--kubeconfig", e.opts.Kubeconfig}, kubectlArgs...)
	}
	if e.opts.Context != "" {
		kubectlArgs = append([]string{"--context", e.opts.Context}, kubectlArgs...)
	}

	runCtx, cancel := context.WithTimeout(ctx, e.opts.CLITimeout)
	defer cancel()

	cmd := exec.CommandContext(runCtx, e.opts.KubectlBin, kubectlArgs...)
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	runErr := cmd.Run()
	timedOut := runCtx.Err() == context.DeadlineExceeded
	exitCode := 0
	if ee, ok := runErr.(*exec.ExitError); ok {
		exitCode = ee.ExitCode()
	} else if runErr != nil && !timedOut {
		return edge.Result{"ok": false, "tool": ToolKubectl, "command": clip(command, 500), "error": "execution failed: " + runErr.Error()}, nil
	}

	ok := exitCode == 0 && !timedOut
	result := edge.Result{
		"ok":        ok,
		"tool":      ToolKubectl,
		"command":   clip(command, 500),
		"verb":      parsed.Verb,
		"resource":  parsed.Resource,
		"read_only": parsed.ReadOnly,
		"exit_code": exitCode,
		"timed_out": timedOut,
		"stderr":    clip(stderr.String(), e.opts.MaxStderr),
	}
	if !ok {
		return result, nil
	}
	if payload := maskedJSONOutput(stdout.String()); payload != nil {
		result["output"] = payload
	} else {
		result["output"] = clip(stdout.String(), e.opts.MaxStdout)
	}
	return result, nil
}

// maskedJSONOutput decodes stdout as JSON and redacts Secret data/stringData fields when the
// response describes a Secret (or a List containing Secrets) — same "data"/"stringData" fields
// the k8s-mask-secret-output guardrail targets, applied structurally here rather than by regex on
// raw text, so masking survives regardless of JSON field order/formatting. Returns nil when stdout
// isn't JSON (e.g. `kubectl get pods` in default table output), leaving it to the plain-text path.
func maskedJSONOutput(raw string) any {
	trimmed := strings.TrimSpace(raw)
	if trimmed == "" || (trimmed[0] != '{' && trimmed[0] != '[') {
		return nil
	}
	var payload any
	if err := json.Unmarshal([]byte(trimmed), &payload); err != nil {
		return nil
	}
	return maskSecretFields(payload)
}

const redacted = "***redacted***"

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

func strArg(args map[string]any, key string) string {
	v, ok := args[key]
	if !ok || v == nil {
		return ""
	}
	return strings.TrimSpace(fmt.Sprint(v))
}

func clip(s string, max int) string {
	if max <= 0 || len(s) <= max {
		return s
	}
	return s[:max]
}
