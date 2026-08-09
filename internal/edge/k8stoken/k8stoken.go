// Package k8stoken mints short-lived Kubernetes ServiceAccount tokens via the Kubernetes-native
// TokenRequest API (authentication/v1), the Kubernetes equivalent of AWS STS AssumeRole — see
// docs/design/kubernetes-access-broker.md §4/§7 in the curlix repo ("Phase 2"). Curlix's backend
// has no network path to a customer's private cluster, so unlike AWS STS (which curlix calls
// directly), this token must be minted here at the edge and relayed back over the existing
// connector channel.
//
// Shells out to `kubectl create token`, same as internal/edge/k8sexec does for kubectl commands
// generally — this repo is pure standard library on purpose, and `kubectl create token` calls the
// exact same TokenRequest API a client-go call would, so no k8s.io/client-go dependency is added.
package k8stoken

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

// ToolKubernetesTokenRequest is the control-plane-side tool name this package handles — MUST
// match whatever name the backend's tool_executor.edge_tool_names() dispatches with.
const ToolKubernetesTokenRequest = "k8s_token_request"

// Options configures the edge TokenRequest minter.
type Options struct {
	Kubeconfig             string        // path to a kubeconfig file (default: kubectl's own default resolution)
	Context                string        // kubeconfig context to use (optional)
	KubectlBin             string        // path to the kubectl binary (default "kubectl")
	CLITimeout             time.Duration // per-invocation timeout (default 30s)
	DefaultDurationSeconds int64         // token TTL when the caller doesn't specify one (default 900 = 15m)
	MaxDurationSeconds     int64         // upper bound a caller may request (default 3600 = 1h)
	MaxStderr              int           // stderr cap in bytes (default 4000)
}

func (o Options) withDefaults() Options {
	if o.KubectlBin == "" {
		o.KubectlBin = "kubectl"
	}
	if o.CLITimeout <= 0 {
		o.CLITimeout = 30 * time.Second
	}
	if o.DefaultDurationSeconds <= 0 {
		o.DefaultDurationSeconds = 900
	}
	if o.MaxDurationSeconds <= 0 {
		o.MaxDurationSeconds = 3600
	}
	if o.MaxStderr <= 0 {
		o.MaxStderr = 4000
	}
	return o
}

// Executor mints tokens with a fixed set of options.
type Executor struct {
	opts Options
}

// New builds an Executor with defaults applied.
func New(opts Options) Executor {
	return Executor{opts: opts.withDefaults()}
}

// Register wires k8s_token_request into the edge registry.
func Register(reg *edge.Registry, opts Options) {
	e := New(opts)
	reg.Register(ToolKubernetesTokenRequest, e.run)
}

// tokenRequestStatus mirrors the fields of authentication/v1.TokenRequest.status this package
// reads out of `kubectl create token -o json`.
type tokenRequestStatus struct {
	Status struct {
		Token               string `json:"token"`
		ExpirationTimestamp string `json:"expirationTimestamp"`
	} `json:"status"`
}

func (e Executor) run(ctx context.Context, args map[string]any) (edge.Result, error) {
	namespace := strArg(args, "namespace")
	serviceAccount := strArg(args, "service_account")
	if namespace == "" || serviceAccount == "" {
		return edge.Result{
			"ok":    false,
			"tool":  ToolKubernetesTokenRequest,
			"error": "namespace and service_account are required",
		}, nil
	}

	duration := clampDuration(intArg(args, "duration_seconds"), e.opts.DefaultDurationSeconds, e.opts.MaxDurationSeconds)

	kubectlArgs := []string{"create", "token", serviceAccount, "-n", namespace, "--duration", fmt.Sprintf("%ds", duration), "-o", "json"}
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
	if runErr != nil || timedOut {
		return edge.Result{
			"ok":        false,
			"tool":      ToolKubernetesTokenRequest,
			"namespace": namespace,
			"error":     "token mint failed: " + clip(stderr.String(), e.opts.MaxStderr),
			"timed_out": timedOut,
		}, nil
	}

	var parsed tokenRequestStatus
	if err := json.Unmarshal(stdout.Bytes(), &parsed); err != nil || parsed.Status.Token == "" {
		return edge.Result{
			"ok":        false,
			"tool":      ToolKubernetesTokenRequest,
			"namespace": namespace,
			"error":     "could not parse TokenRequest response",
		}, nil
	}

	return edge.Result{
		"ok":              true,
		"tool":            ToolKubernetesTokenRequest,
		"namespace":       namespace,
		"service_account": serviceAccount,
		"token":           parsed.Status.Token,
		"expiration":      parsed.Status.ExpirationTimestamp,
	}, nil
}

// clampDuration bounds a caller-requested TTL to (0, max], defaulting to def when unset — the
// same "clamp, don't reject" behavior AWS STS itself applies to AssumeRole session durations.
func clampDuration(requested, def, max int64) int64 {
	if requested <= 0 {
		return def
	}
	if requested > max {
		return max
	}
	return requested
}

func strArg(args map[string]any, key string) string {
	v, ok := args[key]
	if !ok || v == nil {
		return ""
	}
	return strings.TrimSpace(fmt.Sprint(v))
}

func intArg(args map[string]any, key string) int64 {
	v, ok := args[key]
	if !ok || v == nil {
		return 0
	}
	switch n := v.(type) {
	case int64:
		return n
	case int:
		return int64(n)
	case float64:
		return int64(n)
	}
	return 0
}

func clip(s string, max int) string {
	if max <= 0 || len(s) <= max {
		return s
	}
	return s[:max]
}
