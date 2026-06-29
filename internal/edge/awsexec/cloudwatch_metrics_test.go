package awsexec

import (
	"context"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/cloudwatch"
	cwtypes "github.com/aws/aws-sdk-go-v2/service/cloudwatch/types"
	"github.com/aws/aws-sdk-go-v2/service/ecs"
	ecstypes "github.com/aws/aws-sdk-go-v2/service/ecs/types"
	elbv2 "github.com/aws/aws-sdk-go-v2/service/elasticloadbalancingv2"
	elbv2types "github.com/aws/aws-sdk-go-v2/service/elasticloadbalancingv2/types"
)

func TestPeriodForRange(t *testing.T) {
	cases := []struct {
		span int64
		want int
	}{
		{600, 60},
		{3600, 60},
		{3601, 300},
		{86400 * 2, 300},
		{86400 * 3, 900},
	}
	for _, c := range cases {
		if got := periodForRange(0, c.span); got != c.want {
			t.Fatalf("periodForRange(span=%d)=%d want %d", c.span, got, c.want)
		}
	}
}

func TestMetricsTimeWindowClampsEnd(t *testing.T) {
	now := time.Now().Unix()
	start, end := metricsTimeWindow(now-3600, now, 60)
	if !end.Before(time.Now().UTC().Add(-60 * time.Second)) {
		t.Fatalf("end not clamped away from now: %v", end)
	}
	if !end.After(start) {
		t.Fatalf("end %v not after start %v", end, start)
	}
}

func TestAlbMetricQueriesShape(t *testing.T) {
	q, labels := albMetricQueries("app/my-alb/abc", 60)
	if len(q) != 7 || len(labels) != 7 {
		t.Fatalf("want 7 queries/labels, got %d/%d", len(q), len(labels))
	}
	if aws.ToString(q[0].MetricStat.Metric.Namespace) != "AWS/ApplicationELB" {
		t.Fatalf("bad namespace: %s", aws.ToString(q[0].MetricStat.Metric.Namespace))
	}
	if aws.ToString(q[0].Id) != "alb_req" || labels[0].ID != "alb_req" {
		t.Fatalf("bad first id: %s / %s", aws.ToString(q[0].Id), labels[0].ID)
	}
	d := q[0].MetricStat.Metric.Dimensions
	if len(d) != 1 || aws.ToString(d[0].Name) != "LoadBalancer" || aws.ToString(d[0].Value) != "app/my-alb/abc" {
		t.Fatalf("bad dimension: %+v", d)
	}
}

func TestMetricResultsToSeries(t *testing.T) {
	ts := time.Unix(1700000000, 0).UTC()
	results := []cwtypes.MetricDataResult{
		{
			Id:         aws.String("alb_req"),
			Timestamps: []time.Time{ts},
			Values:     []float64{42},
			StatusCode: cwtypes.StatusCodeComplete,
		},
	}
	labels := []idLabel{{"alb_req", "ALB requests"}, {"alb_t5xx", "Target 5xx"}}
	series := metricResultsToSeries(labels, results)
	if len(series) != 2 {
		t.Fatalf("want 2 rows, got %d", len(series))
	}
	dp := series[0]["datapoints"].([]map[string]float64)
	if len(dp) != 1 || dp[0]["v"] != 42 || dp[0]["t"] != 1700000000 {
		t.Fatalf("bad datapoint: %+v", dp)
	}
	if series[0]["status_code"] != "Complete" {
		t.Fatalf("bad status_code: %v", series[0]["status_code"])
	}
	// Missing result still yields a row with empty datapoints (never nil).
	dp2 := series[1]["datapoints"].([]map[string]float64)
	if dp2 == nil || len(dp2) != 0 {
		t.Fatalf("expected empty (non-nil) datapoints, got %+v", dp2)
	}
}

func TestMergeEcsRunningTaskSeriesFillsFromAvg(t *testing.T) {
	series := []map[string]any{
		{"id": "ecs_cpu", "label": "cpu", "datapoints": []map[string]float64{{"t": 1, "v": 5}}},
		{"id": "ecs_tasks", "label": "tasks", "datapoints": []map[string]float64{}},
		{"id": "ecs_tasks_avg", "label": "tasks avg", "datapoints": []map[string]float64{{"t": 1, "v": 3}}},
	}
	out := mergeEcsRunningTaskSeries(series)
	for _, s := range out {
		if s["id"] == "ecs_tasks_avg" {
			t.Fatal("ecs_tasks_avg should be dropped")
		}
	}
	var tasks map[string]any
	for _, s := range out {
		if s["id"] == "ecs_tasks" {
			tasks = s
		}
	}
	dp := tasks["datapoints"].([]map[string]float64)
	if len(dp) != 1 || dp[0]["v"] != 3 {
		t.Fatalf("ecs_tasks not filled from avg: %+v", dp)
	}
}

type fakeMetricsAPI struct {
	pages []*cloudwatch.GetMetricDataOutput
	i     int
}

func (f *fakeMetricsAPI) GetMetricData(ctx context.Context, in *cloudwatch.GetMetricDataInput, optFns ...func(*cloudwatch.Options)) (*cloudwatch.GetMetricDataOutput, error) {
	out := f.pages[f.i]
	f.i++
	return out, nil
}

func TestGetMetricDataPaginated(t *testing.T) {
	api := &fakeMetricsAPI{pages: []*cloudwatch.GetMetricDataOutput{
		{MetricDataResults: []cwtypes.MetricDataResult{{Id: aws.String("a")}}, NextToken: aws.String("next")},
		{MetricDataResults: []cwtypes.MetricDataResult{{Id: aws.String("b")}}},
	}}
	res, err := getMetricDataPaginated(context.Background(), api, nil, time.Unix(0, 0), time.Unix(60, 0))
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	if len(res) != 2 {
		t.Fatalf("want 2 merged results, got %d", len(res))
	}
}

type fakeECS struct {
	svc         ecstypes.Service
	stoppedArns []string
	tasks       []ecstypes.Task
}

func (f *fakeECS) DescribeServices(ctx context.Context, in *ecs.DescribeServicesInput, optFns ...func(*ecs.Options)) (*ecs.DescribeServicesOutput, error) {
	return &ecs.DescribeServicesOutput{Services: []ecstypes.Service{f.svc}}, nil
}
func (f *fakeECS) ListTasks(ctx context.Context, in *ecs.ListTasksInput, optFns ...func(*ecs.Options)) (*ecs.ListTasksOutput, error) {
	return &ecs.ListTasksOutput{TaskArns: f.stoppedArns}, nil
}
func (f *fakeECS) DescribeTasks(ctx context.Context, in *ecs.DescribeTasksInput, optFns ...func(*ecs.Options)) (*ecs.DescribeTasksOutput, error) {
	return &ecs.DescribeTasksOutput{Tasks: f.tasks}, nil
}

type fakeELB struct {
	lbArns []string
}

func (f *fakeELB) DescribeTargetGroups(ctx context.Context, in *elbv2.DescribeTargetGroupsInput, optFns ...func(*elbv2.Options)) (*elbv2.DescribeTargetGroupsOutput, error) {
	return &elbv2.DescribeTargetGroupsOutput{TargetGroups: []elbv2types.TargetGroup{{LoadBalancerArns: f.lbArns}}}, nil
}

func TestRunEcsServiceSnapshot(t *testing.T) {
	exit := int32(137)
	svc := ecstypes.Service{
		RunningCount: 2,
		DesiredCount: 3,
		PendingCount: 1,
		Status:       aws.String("ACTIVE"),
		Deployments: []ecstypes.Deployment{
			{Status: aws.String("PRIMARY"), RolloutState: ecstypes.DeploymentRolloutStateInProgress, DesiredCount: 3, RunningCount: 2, PendingCount: 1, FailedTasks: 1},
		},
		Events: []ecstypes.ServiceEvent{
			{CreatedAt: aws.Time(time.Unix(1700000000, 0)), Message: aws.String("(service x) has started 1 tasks")},
		},
		LoadBalancers: []ecstypes.LoadBalancer{{TargetGroupArn: aws.String("arn:aws:elb:tg/abc")}},
	}
	fe := &fakeECS{
		svc:         svc,
		stoppedArns: []string{"arn:aws:ecs:task/cluster/aaa", "arn:aws:ecs:task/cluster/bbb"},
		tasks: []ecstypes.Task{
			{
				TaskArn:       aws.String("arn:aws:ecs:task/cluster/aaa"),
				StoppedAt:     aws.Time(time.Unix(1700000100, 0)),
				StoppedReason: aws.String("Essential container exited"),
				StopCode:      ecstypes.TaskStopCodeEssentialContainerExited,
				Containers:    []ecstypes.Container{{Name: aws.String("app"), ExitCode: &exit, Reason: aws.String("OOM")}},
			},
			{
				TaskArn:    aws.String("arn:aws:ecs:task/cluster/bbb"),
				StoppedAt:  aws.Time(time.Unix(1700000200, 0)),
				Containers: []ecstypes.Container{{Name: aws.String("app")}},
			},
		},
	}
	fl := &fakeELB{lbArns: []string{"arn:aws:elasticloadbalancing:us-east-1:1:loadbalancer/app/my-alb/abc123"}}

	snap := runEcsServiceSnapshot(context.Background(), fe, fl, "cluster", "svc")
	if snap == nil {
		t.Fatal("nil snapshot")
	}
	if snap["running"] != 2 || snap["desired"] != 3 || snap["pending"] != 1 {
		t.Fatalf("bad counts: %+v", snap)
	}
	if snap["service_status"] != "ACTIVE" {
		t.Fatalf("bad status: %v", snap["service_status"])
	}
	deps := snap["deployments"].([]map[string]any)
	if len(deps) != 1 || deps[0]["rollout_state"] != "IN_PROGRESS" || deps[0]["failed_tasks"] != 1 {
		t.Fatalf("bad deployments: %+v", deps)
	}
	dims := snap["alb_load_balancer_dimensions"].([]string)
	if len(dims) != 1 || dims[0] != "app/my-alb/abc123" {
		t.Fatalf("bad alb dims: %+v", dims)
	}
	stopped := snap["recent_stopped_tasks"].([]map[string]any)
	if len(stopped) != 2 {
		t.Fatalf("want 2 stopped tasks, got %d", len(stopped))
	}
	// Sorted by stopped_at desc → bbb (later) first.
	if stopped[0]["task_id"] != "bbb" {
		t.Fatalf("stopped tasks not sorted desc: %+v", stopped)
	}
	ctrs := stopped[1]["containers"].([]map[string]any)
	if ctrs[0]["exit_code"] != 137 {
		t.Fatalf("bad exit_code: %+v", ctrs[0])
	}
}

func TestAlbDimensionFromARN(t *testing.T) {
	if got := albDimensionFromARN("arn:aws:elasticloadbalancing:us-east-1:1:loadbalancer/app/x/y"); got != "app/x/y" {
		t.Fatalf("got %q", got)
	}
	if got := albDimensionFromARN("arn:aws:elasticloadbalancing:us-east-1:1:loadbalancer/net/x/y"); got != "" {
		t.Fatalf("net LB should be empty, got %q", got)
	}
	if got := albDimensionFromARN("not-an-arn"); got != "" {
		t.Fatalf("expected empty, got %q", got)
	}
}
