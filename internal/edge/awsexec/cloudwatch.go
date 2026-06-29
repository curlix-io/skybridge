package awsexec

import (
	"context"
	"fmt"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/cloudwatchlogs"
	cwltypes "github.com/aws/aws-sdk-go-v2/service/cloudwatchlogs/types"
	"github.com/curlix-io/skybridge/internal/edge"
)

const (
	logsDefaultLookbackMin = 60
	logsMaxLookbackMin     = 1440
)

// logsInsightsAPI is the slice of the CloudWatch Logs client the tool needs (an interface so the
// poll/shape logic is unit-testable without live AWS).
type logsInsightsAPI interface {
	StartQuery(ctx context.Context, in *cloudwatchlogs.StartQueryInput, optFns ...func(*cloudwatchlogs.Options)) (*cloudwatchlogs.StartQueryOutput, error)
	GetQueryResults(ctx context.Context, in *cloudwatchlogs.GetQueryResultsInput, optFns ...func(*cloudwatchlogs.Options)) (*cloudwatchlogs.GetQueryResultsOutput, error)
}

// CloudWatchLogsInsights runs ONE read-only Logs Insights query over one or more log groups and
// returns the rows. It builds a live client from the edge's config and delegates to runLogsInsights.
func (e Executor) CloudWatchLogsInsights(ctx context.Context, args map[string]any) (edge.Result, error) {
	region := strArg(args, "region")
	if region == "" {
		region = e.opts.Region
	}
	cfg, err := e.opts.loadConfig(ctx, region)
	if err != nil {
		return edge.ErrorResult("cloudwatch_logs_insights", "credential resolution failed: "+err.Error()), nil
	}
	client := cloudwatchlogs.NewFromConfig(cfg)
	return e.runLogsInsights(ctx, client, args)
}

func (e Executor) runLogsInsights(ctx context.Context, api logsInsightsAPI, args map[string]any) (edge.Result, error) {
	tool := "cloudwatch_logs_insights"

	query := strArg(args, "query")
	if query == "" {
		return edge.ErrorResult(tool, "Missing required 'query'."), nil
	}
	groups := stringList(args["log_groups"])
	if single := strArg(args, "log_group"); single != "" {
		groups = append(groups, single)
	}
	if len(groups) == 0 {
		return edge.ErrorResult(tool, "Provide log_groups (one or more CloudWatch log group names)."), nil
	}

	minutes := logsDefaultLookbackMin
	if v, ok := intArg(args, "minutes"); ok {
		minutes = clampInt(v, 1, logsMaxLookbackMin)
	}
	end := time.Now().Unix()
	start := end - int64(minutes)*60

	startOut, err := api.StartQuery(ctx, &cloudwatchlogs.StartQueryInput{
		LogGroupNames: groups,
		QueryString:   aws.String(clip(query, 4000)),
		StartTime:     aws.Int64(start),
		EndTime:       aws.Int64(end),
		Limit:         aws.Int32(int32(e.opts.MaxRows)),
	})
	if err != nil {
		return edge.ErrorResult(tool, "CloudWatch Logs Insights start failed: "+err.Error()), nil
	}
	queryID := aws.ToString(startOut.QueryId)

	deadline := time.Now().Add(e.opts.LogsMaxWait)
	for {
		out, err := api.GetQueryResults(ctx, &cloudwatchlogs.GetQueryResultsInput{QueryId: aws.String(queryID)})
		if err != nil {
			return edge.ErrorResult(tool, "CloudWatch Logs Insights results failed: "+err.Error()), nil
		}
		switch out.Status {
		case cwltypes.QueryStatusComplete:
			return logsResult(tool, query, groups, minutes, out), nil
		case cwltypes.QueryStatusFailed, cwltypes.QueryStatusCancelled, cwltypes.QueryStatusTimeout:
			return edge.ErrorResult(tool, fmt.Sprintf("query did not complete (status=%s)", out.Status)), nil
		}
		if time.Now().After(deadline) {
			return edge.ErrorResult(tool, "query timed out waiting for results at the edge"), nil
		}
		select {
		case <-ctx.Done():
			return edge.ErrorResult(tool, "context cancelled"), nil
		case <-time.After(minDur(e.opts.LogsPollEvery, time.Until(deadline))):
		}
	}
}

func logsResult(tool, query string, groups []string, minutes int, out *cloudwatchlogs.GetQueryResultsOutput) edge.Result {
	rows := make([]map[string]string, 0, len(out.Results))
	for _, fields := range out.Results {
		row := make(map[string]string, len(fields))
		for _, f := range fields {
			row[aws.ToString(f.Field)] = aws.ToString(f.Value)
		}
		rows = append(rows, row)
	}
	return edge.Result{
		"ok":         true,
		"tool":       tool,
		"query":      clip(query, 4000),
		"log_groups": groups,
		"minutes":    minutes,
		"row_count":  len(rows),
		"results":    rows,
		"note":       "Read-only CloudWatch Logs Insights query executed at the edge; row-capped.",
	}
}

func stringList(v any) []string {
	raw, ok := v.([]any)
	if !ok {
		return nil
	}
	out := make([]string, 0, len(raw))
	for _, item := range raw {
		if s, ok := item.(string); ok && s != "" {
			out = append(out, s)
		}
	}
	return out
}

func clampInt(v, lo, hi int) int {
	if v < lo {
		return lo
	}
	if v > hi {
		return hi
	}
	return v
}
