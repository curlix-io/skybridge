package awsexec

import "github.com/curlix-io/skybridge/internal/edge"

// Tool names — these MUST match the SaaS-side tool catalog (backend ai_agent/tools_readonly.py) so a
// dispatched tool call resolves to the same capability at the edge.
const (
	ToolAWSReadOnlyCLI         = "aws_readonly_cli"
	ToolCloudWatchLogsInsights = "cloudwatch_logs_insights"
	ToolCloudWatchMetrics      = "cloudwatch_metrics"
)

// Register wires the edge-handled AWS tools into the registry. Only tools that genuinely need live
// customer-account access run here; everything else stays SaaS-side.
func Register(reg *edge.Registry, opts Options) {
	e := New(opts)
	reg.Register(ToolAWSReadOnlyCLI, e.RunReadOnlyCLI)
	reg.Register(ToolCloudWatchLogsInsights, e.CloudWatchLogsInsights)
	reg.Register(ToolCloudWatchMetrics, e.CloudWatchMetrics)
}
