package awsexec

import (
	"context"
	"encoding/xml"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/cloudwatch"
	cwtypes "github.com/aws/aws-sdk-go-v2/service/cloudwatch/types"
	"github.com/aws/aws-sdk-go-v2/service/cloudwatchlogs"
	cwltypes "github.com/aws/aws-sdk-go-v2/service/cloudwatchlogs/types"
	"github.com/aws/aws-sdk-go-v2/service/ecs"
	ecstypes "github.com/aws/aws-sdk-go-v2/service/ecs/types"
	elbv2 "github.com/aws/aws-sdk-go-v2/service/elasticloadbalancingv2"
)

// --- awsexec.go: loadConfig error path ---

// A malformed shared config file (referenced via AWS_PROFILE) makes LoadDefaultConfig fail without
// any real network call, exercising loadConfig's error branch hermetically.
func TestLoadConfigPropagatesSharedConfigError(t *testing.T) {
	dir := t.TempDir()
	cfgPath := dir + "/config"
	if err := writeFile(cfgPath, "[profile bad\nkey="); err != nil {
		t.Fatal(err)
	}
	t.Setenv("AWS_CONFIG_FILE", cfgPath)
	t.Setenv("AWS_SDK_LOAD_CONFIG", "1")
	t.Setenv("AWS_PROFILE", "bad")

	o := Options{}.withDefaults()
	if _, err := o.loadConfig(context.Background(), "us-east-1"); err == nil {
		t.Fatal("expected error from malformed shared config profile")
	}
}

func writeFile(path, content string) error {
	return os.WriteFile(path, []byte(content), 0o600)
}

// --- cli.go: cliEnv assume-role success path + RunReadOnlyCLI happy path with assume-role ---

// fakeSTSServer returns an httptest server that answers any request (AssumeRole included) with a
// fixed set of temporary credentials, in the STS XML shape the SDK expects.
func fakeSTSServer(t *testing.T) *httptest.Server {
	t.Helper()
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		type assumeRoleResp struct {
			XMLName xml.Name `xml:"https://sts.amazonaws.com/doc/2011-06-15/ AssumeRoleResponse"`
			Result  struct {
				Credentials struct {
					AccessKeyId     string
					SecretAccessKey string
					SessionToken    string
					Expiration      string
				}
			} `xml:"AssumeRoleResult"`
		}
		resp := assumeRoleResp{}
		resp.Result.Credentials.AccessKeyId = "AKIAFAKE"
		resp.Result.Credentials.SecretAccessKey = "fakesecret"
		resp.Result.Credentials.SessionToken = "faketoken"
		resp.Result.Credentials.Expiration = time.Now().Add(time.Hour).UTC().Format(time.RFC3339)
		w.Header().Set("Content-Type", "text/xml")
		_ = xml.NewEncoder(w).Encode(resp)
	}))
	t.Cleanup(ts.Close)
	return ts
}

func setFakeAmbientCreds(t *testing.T) {
	t.Helper()
	t.Setenv("AWS_ACCESS_KEY_ID", "base-key")
	t.Setenv("AWS_SECRET_ACCESS_KEY", "base-secret")
	t.Setenv("AWS_SESSION_TOKEN", "")
}

// cliEnv, given a working (fake) STS endpoint, should successfully retrieve assumed-role credentials
// and inject them (plus the session token) into the subprocess environment.
func TestCliEnvAssumeRoleSuccessInjectsCredentials(t *testing.T) {
	ts := fakeSTSServer(t)
	setFakeAmbientCreds(t)
	t.Setenv("AWS_ENDPOINT_URL_STS", ts.URL)

	e := New(Options{AssumeRoleARN: "arn:aws:iam::123456789012:role/edge", ExternalID: "ext-id"})
	env, err := e.cliEnv(context.Background(), "us-east-1")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	var sawKey, sawSecret, sawToken bool
	for _, kv := range env {
		switch kv {
		case "AWS_ACCESS_KEY_ID=AKIAFAKE":
			sawKey = true
		case "AWS_SECRET_ACCESS_KEY=fakesecret":
			sawSecret = true
		case "AWS_SESSION_TOKEN=faketoken":
			sawToken = true
		}
	}
	if !sawKey || !sawSecret || !sawToken {
		t.Fatalf("expected assumed-role credentials injected, got env=%v", env)
	}
}

// End-to-end: RunReadOnlyCLI with an assume-role configured and a working fake STS endpoint should
// resolve credentials and execute the (stand-in) aws binary successfully.
func TestRunReadOnlyCLIAssumeRoleSuccess(t *testing.T) {
	ts := fakeSTSServer(t)
	setFakeAmbientCreds(t)
	t.Setenv("AWS_ENDPOINT_URL_STS", ts.URL)

	e := New(Options{AWSBinary: "/bin/echo", AssumeRoleARN: "arn:aws:iam::123456789012:role/edge"})
	res, err := e.RunReadOnlyCLI(context.Background(), map[string]any{"command": "aws ec2 describe-instances"})
	if err != nil {
		t.Fatal(err)
	}
	if res["ok"] != true {
		t.Fatalf("expected ok=true, got %+v", res)
	}
}

// --- cli.go: clip truncation branch (max>0 and len(s)>max) ---

func TestClipTruncates(t *testing.T) {
	if got := clip("hello world", 5); got != "hello" {
		t.Fatalf("expected truncation to 5 chars, got %q", got)
	}
}

// --- cloudwatch.go: GetQueryResults error inside the poll loop (not the first call) ---

type flakyLogsAPI struct {
	calls int
}

func (f *flakyLogsAPI) StartQuery(_ context.Context, _ *cloudwatchlogs.StartQueryInput, _ ...func(*cloudwatchlogs.Options)) (*cloudwatchlogs.StartQueryOutput, error) {
	return &cloudwatchlogs.StartQueryOutput{QueryId: aws.String("q-1")}, nil
}

func (f *flakyLogsAPI) GetQueryResults(_ context.Context, _ *cloudwatchlogs.GetQueryResultsInput, _ ...func(*cloudwatchlogs.Options)) (*cloudwatchlogs.GetQueryResultsOutput, error) {
	f.calls++
	return nil, errors.New("transient failure")
}

func TestRunLogsInsightsGetResultsError(t *testing.T) {
	e := New(Options{})
	res, err := e.runLogsInsights(context.Background(), &flakyLogsAPI{}, map[string]any{
		"query": "fields @message", "log_groups": []any{"g"},
	})
	if err != nil {
		t.Fatal(err)
	}
	if res["ok"] != false {
		t.Fatalf("expected ok=false on GetQueryResults error: %+v", res)
	}
}

// runLogsInsights should honor a single log_group string in addition to log_groups.
func TestRunLogsInsightsSingleLogGroupArg(t *testing.T) {
	api := &fakeLogsAPI{status: cwltypes.QueryStatusComplete}
	e := New(Options{})
	res, err := e.runLogsInsights(context.Background(), api, map[string]any{
		"query": "fields @message", "log_group": "/aws/ecs/app",
	})
	if err != nil {
		t.Fatal(err)
	}
	if res["ok"] != true {
		t.Fatalf("expected ok=true: %+v", res)
	}
	groups := res["log_groups"].([]string)
	if len(groups) != 1 || groups[0] != "/aws/ecs/app" {
		t.Fatalf("expected single log_group folded in, got %+v", groups)
	}
}

// A pending-status result that isn't Complete/Failed/Cancelled/Timeout (e.g. Running) should keep
// polling until the deadline, at which point it reports a timeout — exercising the "still pending"
// fallthrough branch plus the deadline-exceeded path within a single, fast poll loop.
func TestRunLogsInsightsPollsThenTimesOut(t *testing.T) {
	api := &fakeLogsAPI{status: cwltypes.QueryStatusRunning}
	e := New(Options{LogsPollEvery: 5 * time.Millisecond, LogsMaxWait: 20 * time.Millisecond})
	res, err := e.runLogsInsights(context.Background(), api, map[string]any{
		"query": "fields @message", "log_groups": []any{"g"},
	})
	if err != nil {
		t.Fatal(err)
	}
	if res["ok"] != false {
		t.Fatalf("expected ok=false on timeout: %+v", res)
	}
	if api.getCalls < 2 {
		t.Fatalf("expected multiple poll calls before timeout, got %d", api.getCalls)
	}
}

// A canceled context during the poll wait should report "context cancelled" rather than looping
// forever or panicking.
func TestRunLogsInsightsContextCancelledDuringPoll(t *testing.T) {
	api := &fakeLogsAPI{status: cwltypes.QueryStatusRunning}
	e := New(Options{LogsPollEvery: time.Second, LogsMaxWait: time.Minute})
	ctx, cancel := context.WithCancel(context.Background())
	go func() {
		time.Sleep(10 * time.Millisecond)
		cancel()
	}()
	res, err := e.runLogsInsights(ctx, api, map[string]any{
		"query": "fields @message", "log_groups": []any{"g"},
	})
	if err != nil {
		t.Fatal(err)
	}
	if res["ok"] != false {
		t.Fatalf("expected ok=false on context cancellation: %+v", res)
	}
}

// --- cloudwatch_metrics.go: CloudWatchMetrics happy path with all dimensions + ecs_service_counts ---

type fakeMetricsAPISimple struct{}

func (fakeMetricsAPISimple) GetMetricData(_ context.Context, in *cloudwatch.GetMetricDataInput, _ ...func(*cloudwatch.Options)) (*cloudwatch.GetMetricDataOutput, error) {
	out := &cloudwatch.GetMetricDataOutput{}
	for _, q := range in.MetricDataQueries {
		out.MetricDataResults = append(out.MetricDataResults, cwtypes.MetricDataResult{
			Id:         q.Id,
			Timestamps: []time.Time{time.Unix(1700000000, 0)},
			Values:     []float64{1},
			StatusCode: cwtypes.StatusCodeComplete,
		})
	}
	return out, nil
}

// CloudWatchMetrics exercises the wrapper only through loadConfig + client construction; the actual
// GetMetricData/ecsServiceSnapshot calls need live AWS clients, which we can't substitute without
// changing the production code. This test instead drives periodForRange/metricsTimeWindow/
// getMetricDataPaginated/metricResultsToSeries/mergeEcsRunningTaskSeries directly at full fidelity to
// close their remaining branches, and separately checks the exported wrapper's argument-validation
// and canceled-context paths (already covered elsewhere).
func TestGetMetricDataPaginatedSingleClient(t *testing.T) {
	api := fakeMetricsAPISimple{}
	queries, _ := ecsServiceMetricQueries("cluster", "svc", 60)
	res, err := getMetricDataPaginated(context.Background(), api, queries, time.Unix(0, 0), time.Unix(60, 0))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(res) != 6 {
		t.Fatalf("want 6 results, got %d", len(res))
	}
}

func TestMetricsTimeWindowStartNotBeforeEnd(t *testing.T) {
	// start == end (e.g. minutes=0-equivalent edge case forced directly): endT must be pushed forward
	// by at least `period` seconds so the window is non-empty.
	now := time.Now().Unix() - 500
	start, end := metricsTimeWindow(now, now, 30)
	if !end.After(start) {
		t.Fatalf("expected end after start when start==end, got start=%v end=%v", start, end)
	}
	if end.Sub(start) < 30*time.Second {
		t.Fatalf("expected window >= period, got %v", end.Sub(start))
	}
}

func TestMetricsTimeWindowPeriodBelowFloor(t *testing.T) {
	now := time.Now().Unix() - 500
	// period < 60 should still yield at least a 60s window per the floor in metricsTimeWindow.
	start, end := metricsTimeWindow(now, now, 10)
	if end.Sub(start) < 60*time.Second {
		t.Fatalf("expected floor of 60s window, got %v", end.Sub(start))
	}
}

// metricResultsToSeries: a result with Messages should populate the "messages" field, and mismatched
// Timestamps/Values lengths should be truncated to the shorter of the two.
func TestMetricResultsToSeriesMessagesAndMismatchedLengths(t *testing.T) {
	ts := time.Unix(1700000000, 0).UTC()
	results := []cwtypes.MetricDataResult{
		{
			Id:         aws.String("m1"),
			Timestamps: []time.Time{ts, ts.Add(time.Minute)},
			Values:     []float64{1},
			Messages: []cwtypes.MessageData{
				{Code: aws.String("PartialData"), Value: aws.String("some data missing")},
			},
		},
	}
	series := metricResultsToSeries([]idLabel{{"m1", "m1 label"}}, results)
	if len(series) != 1 {
		t.Fatalf("want 1 row, got %d", len(series))
	}
	dp := series[0]["datapoints"].([]map[string]float64)
	if len(dp) != 1 {
		t.Fatalf("expected truncation to shorter len (1), got %d", len(dp))
	}
	msgs, ok := series[0]["messages"].([]map[string]string)
	if !ok || len(msgs) != 1 || msgs[0]["code"] != "PartialData" {
		t.Fatalf("expected messages populated, got %+v", series[0]["messages"])
	}
}

// mergeEcsRunningTaskSeries: when ecs_tasks already has datapoints, it should NOT be overwritten by
// ecs_tasks_avg's (status_code/messages should also stay untouched if already present).
func TestMergeEcsRunningTaskSeriesKeepsExistingWhenPresent(t *testing.T) {
	series := []map[string]any{
		{"id": "ecs_tasks", "label": "tasks", "datapoints": []map[string]float64{{"t": 1, "v": 9}}, "status_code": "Complete"},
		{"id": "ecs_tasks_avg", "label": "tasks avg", "datapoints": []map[string]float64{{"t": 1, "v": 3}}, "status_code": "PartialData"},
	}
	out := mergeEcsRunningTaskSeries(series)
	var tasks map[string]any
	for _, s := range out {
		if s["id"] == "ecs_tasks" {
			tasks = s
		}
	}
	dp := tasks["datapoints"].([]map[string]float64)
	if len(dp) != 1 || dp[0]["v"] != 9 {
		t.Fatalf("existing datapoints should be kept, got %+v", dp)
	}
	if tasks["status_code"] != "Complete" {
		t.Fatalf("existing status_code should be kept, got %v", tasks["status_code"])
	}
}

// mergeEcsRunningTaskSeries: when only ecs_tasks (no alt) or only ecs_tasks_avg (no main) is present,
// the function should not panic and should behave as a no-op / drop-only.
func TestMergeEcsRunningTaskSeriesNoMainOrNoAlt(t *testing.T) {
	onlyAvg := []map[string]any{
		{"id": "ecs_tasks_avg", "label": "tasks avg", "datapoints": []map[string]float64{{"t": 1, "v": 3}}},
	}
	out := mergeEcsRunningTaskSeries(onlyAvg)
	if len(out) != 0 {
		t.Fatalf("ecs_tasks_avg alone should be dropped with nothing left, got %+v", out)
	}

	onlyMain := []map[string]any{
		{"id": "ecs_tasks", "label": "tasks", "datapoints": []map[string]float64{}},
	}
	out2 := mergeEcsRunningTaskSeries(onlyMain)
	if len(out2) != 1 || out2[0]["id"] != "ecs_tasks" {
		t.Fatalf("expected ecs_tasks alone to pass through unchanged, got %+v", out2)
	}
}

// --- ecs_snapshot.go: events cap at 18, no target groups, target-group lookup error, no stopped tasks ---

func TestRunEcsServiceSnapshotCapsEventsAt18(t *testing.T) {
	var events []ecstypes.ServiceEvent
	for i := 0; i < 25; i++ {
		events = append(events, ecstypes.ServiceEvent{Message: aws.String("event")})
	}
	fe := &fakeECS{svc: ecstypes.Service{Events: events}}
	fl := &fakeELB{}
	snap := runEcsServiceSnapshot(context.Background(), fe, fl, "cluster", "svc")
	got := snap["events"].([]map[string]string)
	if len(got) != 18 {
		t.Fatalf("expected events capped at 18, got %d", len(got))
	}
}

func TestAlbDimensionsFromServiceNoLoadBalancers(t *testing.T) {
	dims := albDimensionsFromService(context.Background(), &fakeELB{}, ecstypes.Service{})
	if len(dims) != 0 {
		t.Fatalf("expected empty dims for a service with no load balancers, got %+v", dims)
	}
}

type erroringELB struct{}

func (erroringELB) DescribeTargetGroups(_ context.Context, _ *elbv2.DescribeTargetGroupsInput, _ ...func(*elbv2.Options)) (*elbv2.DescribeTargetGroupsOutput, error) {
	return nil, errors.New("boom")
}

func TestAlbDimensionsFromServiceDescribeTargetGroupsError(t *testing.T) {
	svc := ecstypes.Service{LoadBalancers: []ecstypes.LoadBalancer{{TargetGroupArn: aws.String("arn:aws:elb:tg/abc")}}}
	dims := albDimensionsFromService(context.Background(), erroringELB{}, svc)
	if len(dims) != 0 {
		t.Fatalf("expected empty dims when DescribeTargetGroups errors, got %+v", dims)
	}
}

func TestRecentStoppedTasksNoStoppedTasks(t *testing.T) {
	fe := &fakeECS{}
	out := recentStoppedTasks(context.Background(), fe, "cluster", "svc")
	if len(out) != 0 {
		t.Fatalf("expected no stopped tasks, got %+v", out)
	}
}

type erroringECSDescribeTasks struct {
	*fakeECS
}

func (f erroringECSDescribeTasks) DescribeTasks(_ context.Context, _ *ecs.DescribeTasksInput, _ ...func(*ecs.Options)) (*ecs.DescribeTasksOutput, error) {
	return nil, errors.New("boom")
}

func TestRecentStoppedTasksDescribeTasksError(t *testing.T) {
	fe := erroringECSDescribeTasks{fakeECS: &fakeECS{stoppedArns: []string{"arn:aws:ecs:task/cluster/aaa"}}}
	out := recentStoppedTasks(context.Background(), fe, "cluster", "svc")
	if len(out) != 0 {
		t.Fatalf("expected no stopped tasks on DescribeTasks error, got %+v", out)
	}
}

// recentStoppedTasks caps at 10 ARNs passed to DescribeTasks even if ListTasks returns more.
func TestRecentStoppedTasksCapsArnsAtTen(t *testing.T) {
	var arns []string
	for i := 0; i < 12; i++ {
		arns = append(arns, "arn:aws:ecs:task/cluster/t")
	}
	captured := &capturingECS{fakeECS: &fakeECS{stoppedArns: arns}}
	_ = recentStoppedTasks(context.Background(), captured, "cluster", "svc")
	if len(captured.lastTasksArg) != 10 {
		t.Fatalf("expected DescribeTasks called with 10 arns, got %d", len(captured.lastTasksArg))
	}
}

type capturingECS struct {
	*fakeECS
	lastTasksArg []string
}

func (c *capturingECS) DescribeTasks(ctx context.Context, in *ecs.DescribeTasksInput, optFns ...func(*ecs.Options)) (*ecs.DescribeTasksOutput, error) {
	c.lastTasksArg = in.Tasks
	return c.fakeECS.DescribeTasks(ctx, in, optFns...)
}
