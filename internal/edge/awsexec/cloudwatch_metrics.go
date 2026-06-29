package awsexec

import (
	"context"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/cloudwatch"
	cwtypes "github.com/aws/aws-sdk-go-v2/service/cloudwatch/types"

	"github.com/curlix-io/skybridge/internal/edge"
)

const (
	metricsDefaultLookbackMin = 60
	metricsMaxLookbackMin     = 1440
	ecsAllServices            = "__all__"
)

// metricsAPI is the slice of the CloudWatch client the metrics tool needs (interface for testing).
type metricsAPI interface {
	GetMetricData(ctx context.Context, in *cloudwatch.GetMetricDataInput, optFns ...func(*cloudwatch.Options)) (*cloudwatch.GetMetricDataOutput, error)
}

// idLabel preserves query-id order so the output series is deterministic (Python relies on dict
// insertion order; Go maps don't, so we keep an explicit ordered list).
type idLabel struct {
	ID    string
	Label string
}

type metricSpec struct {
	id, metricName, stat, label string
}

// CloudWatchMetrics runs read-only CloudWatch GetMetricData for ECS/ALB/CloudFront/EC2 over a recent
// window and returns the per-metric series. Mirrors the SaaS cloudwatch_metrics tool so a dispatched
// call produces the same shape, just executed inside the customer's network.
func (e Executor) CloudWatchMetrics(ctx context.Context, args map[string]any) (edge.Result, error) {
	tool := "cloudwatch_metrics"

	alb := strings.TrimSpace(strArg(args, "alb_load_balancer"))
	ecsCluster := strings.TrimSpace(strArg(args, "ecs_cluster"))
	ecsServiceRaw := strings.TrimSpace(strArg(args, "ecs_service"))
	cfID := strings.TrimSpace(strArg(args, "cloudfront_distribution_id"))
	ec2ID := strings.TrimSpace(strArg(args, "ec2_instance_id"))

	allServices := strings.EqualFold(ecsServiceRaw, ecsAllServices)
	ecsService := ecsServiceRaw

	if alb == "" && !(ecsCluster != "" && ecsService != "") && cfID == "" && ec2ID == "" {
		return edge.ErrorResult(tool, "Provide alb_load_balancer, ecs_cluster+ecs_service, cloudfront_distribution_id, or ec2_instance_id."), nil
	}
	if (ecsCluster != "" && ecsService == "") || (ecsService != "" && ecsCluster == "") {
		return edge.ErrorResult(tool, "ecs_cluster and ecs_service must both be set."), nil
	}

	minutes := metricsDefaultLookbackMin
	if v, ok := intArg(args, "minutes"); ok {
		minutes = clampInt(v, 1, metricsMaxLookbackMin)
	}
	end := time.Now().Unix()
	start := end - int64(minutes)*60
	period := periodForRange(start, end)

	var queries []cwtypes.MetricDataQuery
	var labels []idLabel
	if alb != "" {
		q, l := albMetricQueries(alb, period)
		queries, labels = append(queries, q...), append(labels, l...)
	}
	if ecsCluster != "" && ecsService != "" && allServices {
		q, l := ecsClusterMetricQueries(ecsCluster, period)
		queries, labels = append(queries, q...), append(labels, l...)
	} else if ecsCluster != "" && ecsService != "" {
		q, l := ecsServiceMetricQueries(ecsCluster, ecsService, period)
		queries, labels = append(queries, q...), append(labels, l...)
	}
	if cfID != "" {
		q, l := cloudFrontMetricQueries(cfID, period)
		queries, labels = append(queries, q...), append(labels, l...)
	}
	if ec2ID != "" {
		q, l := ec2MetricQueries(ec2ID, period)
		queries, labels = append(queries, q...), append(labels, l...)
	}

	region := strings.TrimSpace(strArg(args, "region"))
	if region == "" {
		region = e.opts.Region
	}
	cfg, err := e.opts.loadConfig(ctx, region)
	if err != nil {
		return edge.ErrorResult(tool, "credential resolution failed: "+err.Error()), nil
	}
	cw := cloudwatch.NewFromConfig(cfg)

	startTime, endTime := metricsTimeWindow(start, end, period)
	raw, err := getMetricDataPaginated(ctx, cw, queries, startTime, endTime)
	if err != nil {
		return edge.ErrorResult(tool, "GetMetricData failed: "+err.Error()), nil
	}
	series := mergeEcsRunningTaskSeries(metricResultsToSeries(labels, raw))

	res := edge.Result{
		"ok":             true,
		"tool":           tool,
		"minutes":        minutes,
		"region":         region,
		"period_seconds": period,
		"series":         series,
		"note":           "Read-only CloudWatch GetMetricData over the requested window, executed at the edge.",
	}
	// ecs_service_counts: live ECS state for the single-service case (cluster-wide overview stays SaaS-side).
	if ecsCluster != "" && ecsService != "" && !allServices {
		if snap := e.ecsServiceSnapshot(ctx, cfg, region, ecsCluster, ecsService); snap != nil {
			res["ecs_service_counts"] = snap
		} else {
			res["ecs_service_counts"] = nil
		}
	} else {
		res["ecs_service_counts"] = nil
	}
	return res, nil
}

func periodForRange(start, end int64) int {
	span := end - start
	if span < 0 {
		span = 0
	}
	switch {
	case span <= 3600:
		return 60
	case span <= 86400*2:
		return 300
	default:
		return 900
	}
}

// metricsTimeWindow clamps EndTime out of the last ~2 minutes (CloudWatch metrics lag and querying
// through "now" often yields an empty window).
func metricsTimeWindow(start, end int64, period int) (time.Time, time.Time) {
	startT := time.Unix(start, 0).UTC()
	endT := time.Unix(end, 0).UTC()
	latestOK := time.Now().UTC().Add(-120 * time.Second)
	if endT.After(latestOK) {
		endT = latestOK
	}
	if !endT.After(startT) {
		secs := period
		if secs < 60 {
			secs = 60
		}
		endT = startT.Add(time.Duration(secs) * time.Second)
	}
	return startT, endT
}

func buildQueries(namespace string, dims []cwtypes.Dimension, period int, specs []metricSpec) ([]cwtypes.MetricDataQuery, []idLabel) {
	queries := make([]cwtypes.MetricDataQuery, 0, len(specs))
	labels := make([]idLabel, 0, len(specs))
	p := int32(period)
	for _, s := range specs {
		spec := s
		queries = append(queries, cwtypes.MetricDataQuery{
			Id: aws.String(spec.id),
			MetricStat: &cwtypes.MetricStat{
				Metric: &cwtypes.Metric{
					Namespace:  aws.String(namespace),
					MetricName: aws.String(spec.metricName),
					Dimensions: dims,
				},
				Period: aws.Int32(p),
				Stat:   aws.String(spec.stat),
			},
		})
		labels = append(labels, idLabel{ID: spec.id, Label: spec.label})
	}
	return queries, labels
}

func albMetricQueries(lb string, period int) ([]cwtypes.MetricDataQuery, []idLabel) {
	return buildQueries("AWS/ApplicationELB", []cwtypes.Dimension{{Name: aws.String("LoadBalancer"), Value: aws.String(lb)}}, period, []metricSpec{
		{"alb_req", "RequestCount", "Sum", "ALB requests (sum / period)"},
		{"alb_t4xx", "HTTPCode_Target_4XX_Count", "Sum", "Target 4xx (sum / period)"},
		{"alb_e4xx", "HTTPCode_ELB_4XX_Count", "Sum", "ELB 4xx (sum / period)"},
		{"alb_t5xx", "HTTPCode_Target_5XX_Count", "Sum", "Target 5xx (sum / period)"},
		{"alb_e5xx", "HTTPCode_ELB_5XX_Count", "Sum", "ELB 5xx (sum / period)"},
		{"alb_lat", "TargetResponseTime", "Average", "Target response time avg (s)"},
		{"alb_lat_p99", "TargetResponseTime", "p99", "Target response time p99 (s)"},
	})
}

func cloudFrontMetricQueries(distID string, period int) ([]cwtypes.MetricDataQuery, []idLabel) {
	return buildQueries("AWS/CloudFront", []cwtypes.Dimension{{Name: aws.String("DistributionId"), Value: aws.String(distID)}}, period, []metricSpec{
		{"cf_req", "Requests", "Sum", "CloudFront requests (sum / period)"},
	})
}

func ec2MetricQueries(instanceID string, period int) ([]cwtypes.MetricDataQuery, []idLabel) {
	return buildQueries("AWS/EC2", []cwtypes.Dimension{{Name: aws.String("InstanceId"), Value: aws.String(instanceID)}}, period, []metricSpec{
		{"ec2_cpu", "CPUUtilization", "Average", "EC2 CPU %"},
		{"ec2_net_in", "NetworkIn", "Sum", "EC2 network in (bytes)"},
		{"ec2_net_out", "NetworkOut", "Sum", "EC2 network out (bytes)"},
	})
}

func ecsServiceMetricQueries(cluster, service string, period int) ([]cwtypes.MetricDataQuery, []idLabel) {
	return buildQueries("AWS/ECS", []cwtypes.Dimension{
		{Name: aws.String("ClusterName"), Value: aws.String(cluster)},
		{Name: aws.String("ServiceName"), Value: aws.String(service)},
	}, period, []metricSpec{
		{"ecs_cpu", "CPUUtilization", "Average", "ECS CPU %"},
		{"ecs_mem", "MemoryUtilization", "Average", "ECS memory %"},
		{"ecs_tasks", "RunningTaskCount", "Maximum", "ECS running tasks"},
		{"ecs_tasks_avg", "RunningTaskCount", "Average", "ECS running tasks (avg)"},
		{"ecs_rx", "NetworkRxBytes", "Sum", "ECS network RX (bytes)"},
		{"ecs_tx", "NetworkTxBytes", "Sum", "ECS network TX (bytes)"},
	})
}

func ecsClusterMetricQueries(cluster string, period int) ([]cwtypes.MetricDataQuery, []idLabel) {
	return buildQueries("AWS/ECS", []cwtypes.Dimension{{Name: aws.String("ClusterName"), Value: aws.String(cluster)}}, period, []metricSpec{
		{"ecs_cpu", "CPUUtilization", "Average", "ECS CPU % (cluster)"},
		{"ecs_mem", "MemoryUtilization", "Average", "ECS memory % (cluster)"},
		{"ecs_tasks", "RunningTaskCount", "Maximum", "ECS running tasks (cluster)"},
		{"ecs_tasks_avg", "RunningTaskCount", "Average", "ECS running tasks (cluster, avg)"},
		{"ecs_rx", "NetworkRxBytes", "Sum", "ECS network RX (bytes, cluster)"},
		{"ecs_tx", "NetworkTxBytes", "Sum", "ECS network TX (bytes, cluster)"},
	})
}

func getMetricDataPaginated(ctx context.Context, api metricsAPI, queries []cwtypes.MetricDataQuery, start, end time.Time) ([]cwtypes.MetricDataResult, error) {
	var all []cwtypes.MetricDataResult
	var token *string
	for {
		out, err := api.GetMetricData(ctx, &cloudwatch.GetMetricDataInput{
			MetricDataQueries: queries,
			StartTime:         aws.Time(start),
			EndTime:           aws.Time(end),
			NextToken:         token,
		})
		if err != nil {
			return nil, err
		}
		all = append(all, out.MetricDataResults...)
		if out.NextToken == nil || *out.NextToken == "" {
			break
		}
		token = out.NextToken
	}
	return all, nil
}

func metricResultsToSeries(labels []idLabel, results []cwtypes.MetricDataResult) []map[string]any {
	byID := make(map[string]cwtypes.MetricDataResult, len(results))
	for _, r := range results {
		if r.Id != nil {
			byID[*r.Id] = r
		}
	}
	series := make([]map[string]any, 0, len(labels))
	for _, il := range labels {
		r, ok := byID[il.ID]
		datapoints := make([]map[string]float64, 0)
		row := map[string]any{"id": il.ID, "label": il.Label}
		if ok {
			n := len(r.Timestamps)
			if len(r.Values) < n {
				n = len(r.Values)
			}
			for i := 0; i < n; i++ {
				datapoints = append(datapoints, map[string]float64{
					"t": float64(r.Timestamps[i].UnixNano()) / 1e9,
					"v": r.Values[i],
				})
			}
			if r.StatusCode != "" {
				row["status_code"] = string(r.StatusCode)
			}
			var msgs []map[string]string
			for _, m := range r.Messages {
				msgs = append(msgs, map[string]string{
					"code":  clip(aws.ToString(m.Code), 128),
					"value": clip(aws.ToString(m.Value), 2000),
				})
			}
			if len(msgs) > 0 {
				row["messages"] = msgs
			}
		}
		row["datapoints"] = datapoints
		series = append(series, row)
	}
	return series
}

// mergeEcsRunningTaskSeries exposes a single ecs_tasks series, filling from ecs_tasks_avg when the
// Maximum stat returned no points, then drops the helper ecs_tasks_avg row.
func mergeEcsRunningTaskSeries(series []map[string]any) []map[string]any {
	var main, alt map[string]any
	for _, s := range series {
		switch s["id"] {
		case "ecs_tasks":
			main = s
		case "ecs_tasks_avg":
			alt = s
		}
	}
	if main != nil && alt != nil {
		mainPts, _ := main["datapoints"].([]map[string]float64)
		altPts, _ := alt["datapoints"].([]map[string]float64)
		if len(mainPts) == 0 && len(altPts) > 0 {
			main["datapoints"] = altPts
			if _, ok := main["status_code"]; !ok {
				if sc, ok := alt["status_code"]; ok {
					main["status_code"] = sc
				}
			}
			if _, ok := main["messages"]; !ok {
				if ms, ok := alt["messages"]; ok {
					main["messages"] = ms
				}
			}
		}
	}
	out := make([]map[string]any, 0, len(series))
	for _, s := range series {
		if s["id"] == "ecs_tasks_avg" {
			continue
		}
		out = append(out, s)
	}
	return out
}
