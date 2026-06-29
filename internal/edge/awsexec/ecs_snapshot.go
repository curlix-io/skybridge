package awsexec

import (
	"context"
	"sort"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/ecs"
	ecstypes "github.com/aws/aws-sdk-go-v2/service/ecs/types"
	elbv2 "github.com/aws/aws-sdk-go-v2/service/elasticloadbalancingv2"
)

// ecsAPI / elbv2API are the slices of the ECS and ELBv2 clients the snapshot needs (interfaces so the
// shaping logic is unit-testable without live AWS).
type ecsAPI interface {
	DescribeServices(ctx context.Context, in *ecs.DescribeServicesInput, optFns ...func(*ecs.Options)) (*ecs.DescribeServicesOutput, error)
	ListTasks(ctx context.Context, in *ecs.ListTasksInput, optFns ...func(*ecs.Options)) (*ecs.ListTasksOutput, error)
	DescribeTasks(ctx context.Context, in *ecs.DescribeTasksInput, optFns ...func(*ecs.Options)) (*ecs.DescribeTasksOutput, error)
}

type elbv2API interface {
	DescribeTargetGroups(ctx context.Context, in *elbv2.DescribeTargetGroupsInput, optFns ...func(*elbv2.Options)) (*elbv2.DescribeTargetGroupsOutput, error)
}

// ecsServiceSnapshot builds live ECS/ELB clients from cfg and delegates to runEcsServiceSnapshot.
func (e Executor) ecsServiceSnapshot(ctx context.Context, cfg aws.Config, region, cluster, service string) map[string]any {
	_ = region
	return runEcsServiceSnapshot(ctx, ecs.NewFromConfig(cfg), elbv2.NewFromConfig(cfg), cluster, service)
}

// runEcsServiceSnapshot mirrors the SaaS _ecs_service_snapshot: counts + deployment rollout state +
// recent service events + recent stopped-task exit reasons + ALB dimensions. Returns nil when the
// service cannot be described (caller reports a nil ecs_service_counts).
func runEcsServiceSnapshot(ctx context.Context, ecsc ecsAPI, elb elbv2API, cluster, service string) map[string]any {
	cluster = strings.TrimSpace(cluster)
	service = strings.TrimSpace(service)
	if cluster == "" || service == "" {
		return nil
	}
	resp, err := ecsc.DescribeServices(ctx, &ecs.DescribeServicesInput{
		Cluster:  aws.String(cluster),
		Services: []string{service},
	})
	if err != nil || resp == nil || len(resp.Services) == 0 {
		return nil
	}
	s := resp.Services[0]

	albDims := albDimensionsFromService(ctx, elb, s)

	deployments := make([]map[string]any, 0, len(s.Deployments))
	for _, d := range s.Deployments {
		deployments = append(deployments, map[string]any{
			"status":        aws.ToString(d.Status),
			"rollout_state": string(d.RolloutState),
			"desired":       int(d.DesiredCount),
			"running":       int(d.RunningCount),
			"pending":       int(d.PendingCount),
			"failed_tasks":  int(d.FailedTasks),
		})
	}

	events := make([]map[string]string, 0)
	for i, ev := range s.Events {
		if i >= 18 {
			break
		}
		events = append(events, map[string]string{
			"created_at": isoTime(ev.CreatedAt),
			"message":    clip(aws.ToString(ev.Message), 2000),
		})
	}

	recentStopped := recentStoppedTasks(ctx, ecsc, cluster, service)

	return map[string]any{
		"running":                      int(s.RunningCount),
		"desired":                      int(s.DesiredCount),
		"pending":                      int(s.PendingCount),
		"service_status":               aws.ToString(s.Status),
		"deployments":                  deployments,
		"events":                       events,
		"recent_stopped_tasks":         recentStopped,
		"alb_load_balancer_dimensions": albDims,
	}
}

func albDimensionsFromService(ctx context.Context, elb elbv2API, s ecstypes.Service) []string {
	var tgArns []string
	for _, lb := range s.LoadBalancers {
		if a := strings.TrimSpace(aws.ToString(lb.TargetGroupArn)); a != "" {
			tgArns = append(tgArns, a)
		}
	}
	tgArns = sortedUnique(tgArns)
	if len(tgArns) == 0 {
		return []string{}
	}
	dimSet := map[string]struct{}{}
	for i := 0; i < len(tgArns); i += 10 {
		end := i + 10
		if end > len(tgArns) {
			end = len(tgArns)
		}
		out, err := elb.DescribeTargetGroups(ctx, &elbv2.DescribeTargetGroupsInput{TargetGroupArns: tgArns[i:end]})
		if err != nil || out == nil {
			continue
		}
		for _, tg := range out.TargetGroups {
			for _, lbArn := range tg.LoadBalancerArns {
				if dim := albDimensionFromARN(lbArn); dim != "" {
					dimSet[dim] = struct{}{}
				}
			}
		}
	}
	dims := make([]string, 0, len(dimSet))
	for d := range dimSet {
		dims = append(dims, d)
	}
	sort.Strings(dims)
	return dims
}

func albDimensionFromARN(lbARN string) string {
	a := strings.TrimSpace(lbARN)
	const marker = ":loadbalancer/"
	idx := strings.Index(a, marker)
	if idx < 0 {
		return ""
	}
	dim := strings.TrimSpace(a[idx+len(marker):])
	if strings.HasPrefix(dim, "app/") {
		return dim
	}
	return ""
}

func recentStoppedTasks(ctx context.Context, ecsc ecsAPI, cluster, service string) []map[string]any {
	out := make([]map[string]any, 0)
	lt, err := ecsc.ListTasks(ctx, &ecs.ListTasksInput{
		Cluster:       aws.String(cluster),
		ServiceName:   aws.String(service),
		DesiredStatus: ecstypes.DesiredStatusStopped,
		MaxResults:    aws.Int32(8),
	})
	if err != nil || lt == nil || len(lt.TaskArns) == 0 {
		return out
	}
	arns := lt.TaskArns
	if len(arns) > 10 {
		arns = arns[:10]
	}
	dt, err := ecsc.DescribeTasks(ctx, &ecs.DescribeTasksInput{Cluster: aws.String(cluster), Tasks: arns})
	if err != nil || dt == nil {
		return out
	}
	for _, t := range dt.Tasks {
		arn := aws.ToString(t.TaskArn)
		taskID := arn
		if i := strings.LastIndex(arn, "/"); i >= 0 {
			taskID = arn[i+1:]
		}
		containers := make([]map[string]any, 0, len(t.Containers))
		for _, c := range t.Containers {
			var exit any
			if c.ExitCode != nil {
				exit = int(*c.ExitCode)
			}
			containers = append(containers, map[string]any{
				"name":      aws.ToString(c.Name),
				"exit_code": exit,
				"reason":    clip(aws.ToString(c.Reason), 2000),
			})
		}
		out = append(out, map[string]any{
			"task_id":        clip(taskID, 128),
			"stopped_at":     isoTime(t.StoppedAt),
			"stopped_reason": clip(aws.ToString(t.StoppedReason), 2000),
			"stop_code":      clip(string(t.StopCode), 128),
			"containers":     containers,
		})
	}
	sort.SliceStable(out, func(i, j int) bool {
		return toStr(out[i]["stopped_at"]) > toStr(out[j]["stopped_at"])
	})
	return out
}

func isoTime(t *time.Time) string {
	if t == nil {
		return ""
	}
	return t.UTC().Format(time.RFC3339)
}

func sortedUnique(in []string) []string {
	set := map[string]struct{}{}
	for _, s := range in {
		set[s] = struct{}{}
	}
	out := make([]string, 0, len(set))
	for s := range set {
		out = append(out, s)
	}
	sort.Strings(out)
	return out
}

func toStr(v any) string {
	s, _ := v.(string)
	return s
}
