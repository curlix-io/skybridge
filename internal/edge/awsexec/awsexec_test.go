package awsexec

import (
	"context"
	"errors"
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/cloudwatchlogs"
	cwltypes "github.com/aws/aws-sdk-go-v2/service/cloudwatchlogs/types"
)

type fakeLogsAPI struct {
	startErr error
	results  [][]cwltypes.ResultField
	status   cwltypes.QueryStatus
	getCalls int
	getErr   error
}

func (f *fakeLogsAPI) StartQuery(_ context.Context, _ *cloudwatchlogs.StartQueryInput, _ ...func(*cloudwatchlogs.Options)) (*cloudwatchlogs.StartQueryOutput, error) {
	if f.startErr != nil {
		return nil, f.startErr
	}
	return &cloudwatchlogs.StartQueryOutput{QueryId: aws.String("q-1")}, nil
}

func (f *fakeLogsAPI) GetQueryResults(_ context.Context, _ *cloudwatchlogs.GetQueryResultsInput, _ ...func(*cloudwatchlogs.Options)) (*cloudwatchlogs.GetQueryResultsOutput, error) {
	f.getCalls++
	if f.getErr != nil {
		return nil, f.getErr
	}
	return &cloudwatchlogs.GetQueryResultsOutput{Status: f.status, Results: f.results}, nil
}

func TestRunLogsInsightsComplete(t *testing.T) {
	api := &fakeLogsAPI{
		status: cwltypes.QueryStatusComplete,
		results: [][]cwltypes.ResultField{
			{{Field: aws.String("@timestamp"), Value: aws.String("t1")}, {Field: aws.String("@message"), Value: aws.String("ERROR boom")}},
		},
	}
	e := New(Options{})
	res, err := e.runLogsInsights(context.Background(), api, map[string]any{
		"query":      "fields @timestamp,@message | limit 10",
		"log_groups": []any{"/aws/ecs/app"},
	})
	if err != nil {
		t.Fatal(err)
	}
	if res["ok"] != true {
		t.Fatalf("expected ok: %+v", res)
	}
	if res["row_count"] != 1 {
		t.Fatalf("row_count = %v", res["row_count"])
	}
	rows := res["results"].([]map[string]string)
	if rows[0]["@message"] != "ERROR boom" {
		t.Fatalf("row content wrong: %+v", rows)
	}
}

func TestRunLogsInsightsMissingQuery(t *testing.T) {
	e := New(Options{})
	res, _ := e.runLogsInsights(context.Background(), &fakeLogsAPI{}, map[string]any{"log_groups": []any{"g"}})
	if res["ok"] != false {
		t.Fatalf("missing query should fail: %+v", res)
	}
}

func TestRunLogsInsightsMissingGroups(t *testing.T) {
	e := New(Options{})
	res, _ := e.runLogsInsights(context.Background(), &fakeLogsAPI{}, map[string]any{"query": "x"})
	if res["ok"] != false {
		t.Fatalf("missing groups should fail: %+v", res)
	}
}

func TestRunLogsInsightsFailedStatus(t *testing.T) {
	api := &fakeLogsAPI{status: cwltypes.QueryStatusFailed}
	e := New(Options{})
	res, _ := e.runLogsInsights(context.Background(), api, map[string]any{"query": "x", "log_groups": []any{"g"}})
	if res["ok"] != false {
		t.Fatalf("failed status should yield ok=false: %+v", res)
	}
}

func TestRunLogsInsightsStartError(t *testing.T) {
	api := &fakeLogsAPI{startErr: errors.New("nope")}
	e := New(Options{})
	res, _ := e.runLogsInsights(context.Background(), api, map[string]any{"query": "x", "log_groups": []any{"g"}})
	if res["ok"] != false {
		t.Fatalf("start error should yield ok=false: %+v", res)
	}
}

func TestRunReadOnlyCLIRejectsBadCommand(t *testing.T) {
	e := New(Options{})
	res, err := e.RunReadOnlyCLI(context.Background(), map[string]any{"command": "aws ec2 terminate-instances"})
	if err != nil {
		t.Fatal(err)
	}
	if res["ok"] != false {
		t.Fatalf("mutating command should be rejected: %+v", res)
	}
}

func TestRunReadOnlyCLIHappyPath(t *testing.T) {
	// Use /bin/echo as a stand-in for the aws binary to exercise the exec + capture path.
	e := New(Options{AWSBinary: "/bin/echo"})
	res, err := e.RunReadOnlyCLI(context.Background(), map[string]any{"command": "aws ec2 describe-instances", "aws_region": "us-east-1"})
	if err != nil {
		t.Fatal(err)
	}
	if res["ok"] != true {
		t.Fatalf("expected ok: %+v", res)
	}
	if res["exit_code"] != 0 {
		t.Fatalf("exit_code = %v", res["exit_code"])
	}
	if got := res["stdout"].(string); got != "ec2 describe-instances\n" {
		t.Fatalf("stdout = %q", got)
	}
}

func TestScrubAWSEnv(t *testing.T) {
	in := []string{"PATH=/usr/bin", "AWS_ACCESS_KEY_ID=AKIA", "AWS_PROFILE=admin", "HOME=/root", "AWS_SESSION_TOKEN=tok"}
	out := scrubAWSEnv(in)
	for _, kv := range out {
		if kv == "AWS_ACCESS_KEY_ID=AKIA" || kv == "AWS_PROFILE=admin" || kv == "AWS_SESSION_TOKEN=tok" {
			t.Fatalf("credential var not scrubbed: %q", kv)
		}
	}
	// Non-AWS vars remain.
	var hasPath bool
	for _, kv := range out {
		if kv == "PATH=/usr/bin" {
			hasPath = true
		}
	}
	if !hasPath {
		t.Fatal("PATH should be preserved")
	}
}
