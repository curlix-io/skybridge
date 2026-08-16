package awsexec

import (
	"context"
	"os"
	"testing"
	"time"

	"github.com/curlix-io/skybridge/internal/edge"
)

// --- awsexec.go ---

func TestIntArgAcceptsIntAndFloat64(t *testing.T) {
	if v, ok := intArg(map[string]any{"n": 5}, "n"); !ok || v != 5 {
		t.Fatalf("int case: v=%d ok=%v", v, ok)
	}
	if v, ok := intArg(map[string]any{"n": float64(7)}, "n"); !ok || v != 7 {
		t.Fatalf("float64 case: v=%d ok=%v", v, ok)
	}
	if _, ok := intArg(map[string]any{"n": "not a number"}, "n"); ok {
		t.Fatal("expected ok=false for non-numeric value")
	}
	if _, ok := intArg(map[string]any{}, "missing"); ok {
		t.Fatal("expected ok=false for missing key")
	}
}

// loadConfig itself never makes a network call (it just assembles config from env/files/ambient
// role chain); with no AssumeRoleARN it should return without error regardless of ambient
// credentials.
func TestLoadConfigNoAssumeRole(t *testing.T) {
	o := Options{}.withDefaults()
	cfg, err := o.loadConfig(context.Background(), "us-east-1")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if cfg.Region != "us-east-1" {
		t.Fatalf("region not applied: %q", cfg.Region)
	}
}

// With AssumeRoleARN set, loadConfig wraps the credentials in an AssumeRoleProvider (lazy — no
// network call happens until Retrieve is called), so this stays hermetic.
func TestLoadConfigWithAssumeRoleIsLazy(t *testing.T) {
	o := Options{AssumeRoleARN: "arn:aws:iam::123456789012:role/edge", ExternalID: "ext-id"}.withDefaults()
	cfg, err := o.loadConfig(context.Background(), "")
	if err != nil {
		t.Fatalf("unexpected error building lazy assume-role config: %v", err)
	}
	if cfg.Credentials == nil {
		t.Fatal("expected credentials provider to be set")
	}
}

// --- cli.go ---

func TestCliEnvAssumeRoleErrorPropagatesOnCanceledContext(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	e := New(Options{AssumeRoleARN: "arn:aws:iam::123456789012:role/edge"})
	if _, err := e.cliEnv(ctx, "us-east-1"); err == nil {
		t.Fatal("expected error retrieving assume-role credentials with a canceled context")
	}
}

func TestCliEnvNoAssumeRoleSetsRegion(t *testing.T) {
	e := New(Options{})
	env, err := e.cliEnv(context.Background(), "us-west-2")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	var sawRegion bool
	for _, kv := range env {
		if kv == "AWS_REGION=us-west-2" {
			sawRegion = true
		}
	}
	if !sawRegion {
		t.Fatalf("expected AWS_REGION to be set: %v", env)
	}
}

func TestRunReadOnlyCLITimesOut(t *testing.T) {
	// argv[1:] (everything after "aws" in the command string) is passed straight through as the
	// subprocess's argv, so AWSBinary must tolerate arbitrary read-only-looking args like
	// "ec2 describe-instances" — /bin/sleep rejects those as an invalid duration and exits
	// immediately instead of actually blocking, racing the timeout rather than exercising it. Use a
	// script that ignores its args and just sleeps.
	dir := t.TempDir()
	script := dir + "/aws"
	if err := os.WriteFile(script, []byte("#!/bin/sh\nsleep 999\n"), 0o755); err != nil {
		t.Fatalf("write script: %v", err)
	}
	e := New(Options{AWSBinary: script, CLITimeout: 20 * time.Millisecond})
	res, err := e.RunReadOnlyCLI(context.Background(), map[string]any{"command": "aws ec2 describe-instances"})
	if err != nil {
		t.Fatal(err)
	}
	if res["timed_out"] != true {
		t.Fatalf("expected timed_out=true: %+v", res)
	}
	if res["ok"] != false {
		t.Fatalf("timed out run should be ok=false: %+v", res)
	}
}

// TestRunReadOnlyCLITimesOutWithOrphanedGrandchild is the regression test for a real CI hang: a
// timed-out aws process that had backgrounded its own child before dying leaves that child holding
// the inherited stdout/stderr pipes open. exec.CommandContext's default Cancel only kills the
// direct child, so without cmd.WaitDelay, Wait (called by Run) blocks forever waiting for those
// pipes to reach EOF — which happened for real in CI (a 600s job-level timeout, not the 20ms
// CLITimeout below). WaitDelay must force the pipes closed so this returns promptly regardless.
func TestRunReadOnlyCLITimesOutWithOrphanedGrandchild(t *testing.T) {
	dir := t.TempDir()
	script := dir + "/aws"
	// The backgrounded `sleep 999 &` inherits the parent's stdout/stderr fds and outlives it once
	// the parent (this script's own shell process, the direct child Run() started) is killed.
	if err := os.WriteFile(script, []byte("#!/bin/sh\nsleep 999 &\nsleep 999\n"), 0o755); err != nil {
		t.Fatalf("write script: %v", err)
	}
	e := New(Options{AWSBinary: script, CLITimeout: 20 * time.Millisecond})

	done := make(chan struct{})
	var res edge.Result
	var err error
	go func() {
		res, err = e.RunReadOnlyCLI(context.Background(), map[string]any{"command": "aws ec2 describe-instances"})
		close(done)
	}()

	select {
	case <-done:
	case <-time.After(10 * time.Second):
		t.Fatal("RunReadOnlyCLI did not return within 10s — orphaned grandchild wedged the pipe wait")
	}
	if err != nil {
		t.Fatal(err)
	}
	if res["timed_out"] != true {
		t.Fatalf("expected timed_out=true: %+v", res)
	}
}

func TestRunReadOnlyCLIExecutionFailsForMissingBinary(t *testing.T) {
	e := New(Options{AWSBinary: "/nonexistent/binary/does-not-exist"})
	res, err := e.RunReadOnlyCLI(context.Background(), map[string]any{"command": "aws ec2 describe-instances"})
	if err != nil {
		t.Fatal(err)
	}
	if res["ok"] != false {
		t.Fatalf("missing binary should be ok=false: %+v", res)
	}
}

func TestRunReadOnlyCLIUnparseableCommand(t *testing.T) {
	e := New(Options{})
	res, err := e.RunReadOnlyCLI(context.Background(), map[string]any{"command": "'unterminated"})
	if err != nil {
		t.Fatal(err)
	}
	if res["ok"] != false {
		t.Fatalf("unparseable command should be ok=false: %+v", res)
	}
}

func TestRunReadOnlyCLICredentialResolutionFails(t *testing.T) {
	e := New(Options{AssumeRoleARN: "arn:aws:iam::123456789012:role/edge"})
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	res, err := e.RunReadOnlyCLI(ctx, map[string]any{"command": "aws ec2 describe-instances"})
	if err != nil {
		t.Fatal(err)
	}
	if res["ok"] != false {
		t.Fatalf("expected credential resolution failure: %+v", res)
	}
}

func TestIndexByteNoMatch(t *testing.T) {
	if got := indexByte("NOEQUALSIGN", '='); got != -1 {
		t.Fatalf("expected -1, got %d", got)
	}
}

func TestClipNoTruncationNeeded(t *testing.T) {
	if got := clip("short", 0); got != "short" {
		t.Fatalf("max<=0 should return input unchanged, got %q", got)
	}
	if got := clip("short", 100); got != "short" {
		t.Fatalf("len(s)<=max should return input unchanged, got %q", got)
	}
}

func TestMinDur(t *testing.T) {
	if got := minDur(time.Second, 2*time.Second); got != time.Second {
		t.Fatalf("expected 1s, got %v", got)
	}
	if got := minDur(3*time.Second, time.Second); got != time.Second {
		t.Fatalf("expected 1s, got %v", got)
	}
}

// --- cloudwatch.go ---

// CloudWatchLogsInsights builds a live client and delegates to runLogsInsights (already covered
// via fakeLogsAPI); a canceled context makes the StartQuery call fail immediately without any real
// network round trip, exercising the wrapper's loadConfig + client-construction + delegation path
// hermetically.
func TestCloudWatchLogsInsightsWrapperCanceledContext(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	e := New(Options{Region: "us-east-1"})
	res, err := e.CloudWatchLogsInsights(ctx, map[string]any{"query": "fields @message", "log_groups": []any{"g"}})
	if err != nil {
		t.Fatal(err)
	}
	if res["ok"] != false {
		t.Fatalf("expected ok=false on canceled context: %+v", res)
	}
}

func TestClampInt(t *testing.T) {
	if got := clampInt(5, 1, 10); got != 5 {
		t.Fatalf("in-range should be unchanged, got %d", got)
	}
	if got := clampInt(-1, 1, 10); got != 1 {
		t.Fatalf("below range should clamp to lo, got %d", got)
	}
	if got := clampInt(50, 1, 10); got != 10 {
		t.Fatalf("above range should clamp to hi, got %d", got)
	}
}

// --- cloudwatch_metrics.go ---

func TestCloudWatchMetricsValidationErrors(t *testing.T) {
	e := New(Options{})
	res, err := e.CloudWatchMetrics(context.Background(), map[string]any{})
	if err != nil {
		t.Fatal(err)
	}
	if res["ok"] != false {
		t.Fatalf("no target dims should fail: %+v", res)
	}

	res2, _ := e.CloudWatchMetrics(context.Background(), map[string]any{"ecs_cluster": "c"})
	if res2["ok"] != false {
		t.Fatalf("cluster without service should fail: %+v", res2)
	}

	res3, _ := e.CloudWatchMetrics(context.Background(), map[string]any{"ecs_service": "s"})
	if res3["ok"] != false {
		t.Fatalf("service without cluster should fail: %+v", res3)
	}
}

// A canceled context drives CloudWatchMetrics through query construction for every dimension type
// (ALB, ECS single-service, ECS all-services/cluster-wide, CloudFront, EC2) and into the
// GetMetricData call, which fails immediately (no real network reached) — this exercises the
// wrapper's assembly logic (query building, ecs_service_counts branch) hermetically.
func TestCloudWatchMetricsCanceledContextAllDimensions(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	e := New(Options{Region: "us-east-1"})

	cases := []map[string]any{
		{"alb_load_balancer": "app/my-alb/abc"},
		{"ecs_cluster": "c", "ecs_service": "s"},
		{"ecs_cluster": "c", "ecs_service": "__all__"},
		{"cloudfront_distribution_id": "E123"},
		{"ec2_instance_id": "i-abc"},
	}
	for _, args := range cases {
		res, err := e.CloudWatchMetrics(ctx, args)
		if err != nil {
			t.Fatalf("args=%v: unexpected error: %v", args, err)
		}
		if res["ok"] != false {
			t.Fatalf("args=%v: expected ok=false on canceled context, got %+v", args, res)
		}
	}
}

func TestCloudFrontMetricQueriesShape(t *testing.T) {
	q, labels := cloudFrontMetricQueries("E123", 60)
	if len(q) != 1 || len(labels) != 1 {
		t.Fatalf("want 1 query/label, got %d/%d", len(q), len(labels))
	}
	if labels[0].ID != "cf_req" {
		t.Fatalf("unexpected label id: %s", labels[0].ID)
	}
}

func TestEC2MetricQueriesShape(t *testing.T) {
	q, labels := ec2MetricQueries("i-abc", 60)
	if len(q) != 3 || len(labels) != 3 {
		t.Fatalf("want 3 queries/labels, got %d/%d", len(q), len(labels))
	}
}

func TestEcsServiceMetricQueriesShape(t *testing.T) {
	q, labels := ecsServiceMetricQueries("cluster", "svc", 60)
	if len(q) != 6 || len(labels) != 6 {
		t.Fatalf("want 6 queries/labels, got %d/%d", len(q), len(labels))
	}
	if len(q[0].MetricStat.Metric.Dimensions) != 2 {
		t.Fatalf("expected 2 dimensions (cluster+service), got %d", len(q[0].MetricStat.Metric.Dimensions))
	}
}

func TestEcsClusterMetricQueriesShape(t *testing.T) {
	q, labels := ecsClusterMetricQueries("cluster", 60)
	if len(q) != 6 || len(labels) != 6 {
		t.Fatalf("want 6 queries/labels, got %d/%d", len(q), len(labels))
	}
	if len(q[0].MetricStat.Metric.Dimensions) != 1 {
		t.Fatalf("expected 1 dimension (cluster only), got %d", len(q[0].MetricStat.Metric.Dimensions))
	}
}

// --- ecs_snapshot.go ---

// ecsServiceSnapshot is a thin wrapper building live ECS/ELB clients from cfg; a canceled context
// makes DescribeServices fail immediately (no real network reached), exercising the wrapper without
// needing live AWS.
func TestEcsServiceSnapshotWrapperCanceledContext(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	e := New(Options{})
	cfg, err := e.opts.loadConfig(context.Background(), "us-east-1")
	if err != nil {
		t.Fatalf("loadConfig: %v", err)
	}
	snap := e.ecsServiceSnapshot(ctx, cfg, "us-east-1", "cluster", "service")
	if snap != nil {
		t.Fatalf("expected nil snapshot on canceled-context DescribeServices failure, got %+v", snap)
	}
}

func TestIsoTimeNil(t *testing.T) {
	if got := isoTime(nil); got != "" {
		t.Fatalf("expected empty string for nil time, got %q", got)
	}
}

// --- register.go ---

func TestRegisterWiresAllTools(t *testing.T) {
	reg := edge.NewRegistry()
	Register(reg, Options{})
	for _, name := range []string{ToolAWSReadOnlyCLI, ToolCloudWatchLogsInsights, ToolCloudWatchMetrics} {
		if !reg.Has(name) {
			t.Fatalf("expected %q to be registered", name)
		}
	}
}
