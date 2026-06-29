package awsexec

import (
	"bytes"
	"context"
	"os"
	"os/exec"
	"time"

	"github.com/curlix-io/skybridge/internal/edge"
)

// RunReadOnlyCLI validates and executes a single read-only `aws` invocation locally, returning its
// captured output. The command is checked against the read-only policy first; only `aws <service>
// <read-op>` style commands are allowed. Credentials come from the host's ambient role (or the
// configured assume-role); the region can be overridden per call via aws_region.
func (e Executor) RunReadOnlyCLI(ctx context.Context, args map[string]any) (edge.Result, error) {
	tool := "aws_readonly_cli"
	command := strArg(args, "command")
	region := strArg(args, "aws_region")
	if region == "" {
		region = e.opts.Region
	}

	if ok, reason := edge.ValidateReadOnlyAWSCommand(command); !ok {
		return edge.Result{"ok": false, "tool": tool, "command": clip(command, 500), "error": "Command rejected by read-only policy: " + reason}, nil
	}
	argv, err := edge.SplitCommand(command)
	if err != nil || len(argv) < 2 || argv[0] != "aws" {
		return edge.Result{"ok": false, "tool": tool, "command": clip(command, 500), "error": "could not parse command"}, nil
	}

	env, err := e.cliEnv(ctx, region)
	if err != nil {
		return edge.Result{"ok": false, "tool": tool, "command": clip(command, 500), "error": "credential resolution failed: " + err.Error()}, nil
	}

	runCtx, cancel := context.WithTimeout(ctx, e.opts.CLITimeout)
	defer cancel()

	cmd := exec.CommandContext(runCtx, e.opts.AWSBinary, argv[1:]...)
	cmd.Env = env
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	runErr := cmd.Run()
	timedOut := runCtx.Err() == context.DeadlineExceeded
	exitCode := 0
	if ee, ok := runErr.(*exec.ExitError); ok {
		exitCode = ee.ExitCode()
	} else if runErr != nil && !timedOut {
		return edge.Result{"ok": false, "tool": tool, "command": clip(command, 500), "error": "execution failed: " + runErr.Error()}, nil
	}

	return edge.Result{
		"ok":         exitCode == 0 && !timedOut,
		"tool":       tool,
		"command":    clip(command, 500),
		"aws_region": region,
		"exit_code":  exitCode,
		"timed_out":  timedOut,
		"stdout":     clip(stdout.String(), e.opts.MaxStdout),
		"stderr":     clip(stderr.String(), e.opts.MaxStderr),
		"note":       "Read-only AWS CLI executed at the edge.",
	}, nil
}

// cliEnv builds the environment for the aws subprocess: the host environment with AWS credential
// variables stripped, the region set, and (when an assume-role is configured) fresh temporary
// credentials injected so the command is scoped to that role.
func (e Executor) cliEnv(ctx context.Context, region string) ([]string, error) {
	base := scrubAWSEnv(os.Environ())
	if region != "" {
		base = append(base, "AWS_DEFAULT_REGION="+region, "AWS_REGION="+region)
	}
	if e.opts.AssumeRoleARN == "" {
		return base, nil
	}
	cfg, err := e.opts.loadConfig(ctx, region)
	if err != nil {
		return nil, err
	}
	creds, err := cfg.Credentials.Retrieve(ctx)
	if err != nil {
		return nil, err
	}
	base = append(base,
		"AWS_ACCESS_KEY_ID="+creds.AccessKeyID,
		"AWS_SECRET_ACCESS_KEY="+creds.SecretAccessKey,
	)
	if creds.SessionToken != "" {
		base = append(base, "AWS_SESSION_TOKEN="+creds.SessionToken)
	}
	return base, nil
}

// scrubAWSEnv removes inherited AWS credential/profile variables so the subprocess can't pick up
// ambient long-lived keys when we intend to scope it to an assumed role.
func scrubAWSEnv(env []string) []string {
	drop := map[string]bool{
		"AWS_ACCESS_KEY_ID": true, "AWS_SECRET_ACCESS_KEY": true, "AWS_SESSION_TOKEN": true,
		"AWS_PROFILE": true, "AWS_DEFAULT_PROFILE": true,
	}
	out := env[:0:0]
	for _, kv := range env {
		key := kv
		if i := indexByte(kv, '='); i >= 0 {
			key = kv[:i]
		}
		if drop[key] {
			continue
		}
		out = append(out, kv)
	}
	return out
}

func indexByte(s string, b byte) int {
	for i := 0; i < len(s); i++ {
		if s[i] == b {
			return i
		}
	}
	return -1
}

func clip(s string, max int) string {
	if max <= 0 || len(s) <= max {
		return s
	}
	return s[:max]
}

// minDur returns the smaller of two durations.
func minDur(a, b time.Duration) time.Duration {
	if a < b {
		return a
	}
	return b
}
