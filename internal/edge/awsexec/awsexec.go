// Package awsexec runs the live, read-only AWS tools at the customer edge. It is the only part of
// the edge that touches the customer's AWS account: it uses the host's ambient IAM role (optionally
// assuming a configured role) so raw cloud data is gathered locally and only results travel back to
// the SaaS control plane.
//
// Three execution styles, matching the SaaS-side tool catalog:
//   - aws_readonly_cli         — validate one read-only `aws` invocation and exec it (generic escape hatch)
//   - cloudwatch_logs_insights — structured CloudWatch Logs Insights query via the SDK
//   - cloudwatch_metrics       — structured CloudWatch GetMetricData (ECS/ALB/CloudFront/EC2) via the SDK
//
// Only the tools registered here run at the edge; anything not registered is reported back as
// "not handled at the edge".
package awsexec

import (
	"context"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	awsconfig "github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/credentials/stscreds"
	"github.com/aws/aws-sdk-go-v2/service/sts"
)

// Executor runs the edge AWS tools with a fixed set of options.
type Executor struct {
	opts Options
}

// New builds an Executor, applying defaults to unset options.
func New(opts Options) Executor {
	return Executor{opts: opts.withDefaults()}
}

// Options configures the edge AWS executor.
type Options struct {
	Region        string        // default region when a tool omits one
	AssumeRoleARN string        // optional role to assume (else ambient credentials are used)
	ExternalID    string        // optional external id for the assume-role
	AWSBinary     string        // path to the aws CLI (default "aws")
	CLITimeout    time.Duration // per-CLI-invocation timeout (default 30s)
	MaxStdout     int           // stdout cap in bytes (default 6000)
	MaxStderr     int           // stderr cap in bytes (default 2000)
	LogsPollEvery time.Duration // Logs Insights poll interval (default 1s)
	LogsMaxWait   time.Duration // Logs Insights overall wait cap (default 30s)
	MaxRows       int           // row cap for query results (default 60)
}

func (o Options) withDefaults() Options {
	if o.AWSBinary == "" {
		o.AWSBinary = "aws"
	}
	if o.CLITimeout <= 0 {
		o.CLITimeout = 30 * time.Second
	}
	if o.MaxStdout <= 0 {
		o.MaxStdout = 6000
	}
	if o.MaxStderr <= 0 {
		o.MaxStderr = 2000
	}
	if o.LogsPollEvery <= 0 {
		o.LogsPollEvery = time.Second
	}
	if o.LogsMaxWait <= 0 {
		o.LogsMaxWait = 30 * time.Second
	}
	if o.MaxRows <= 0 {
		o.MaxRows = 60
	}
	return o
}

// loadConfig builds an aws.Config from the ambient environment/role, optionally assuming a role.
func (o Options) loadConfig(ctx context.Context, region string) (aws.Config, error) {
	var opts []func(*awsconfig.LoadOptions) error
	if region != "" {
		opts = append(opts, awsconfig.WithRegion(region))
	}
	cfg, err := awsconfig.LoadDefaultConfig(ctx, opts...)
	if err != nil {
		return aws.Config{}, err
	}
	if o.AssumeRoleARN != "" {
		stsClient := sts.NewFromConfig(cfg)
		provider := stscreds.NewAssumeRoleProvider(stsClient, o.AssumeRoleARN, func(p *stscreds.AssumeRoleOptions) {
			p.RoleSessionName = "skybridge-edge"
			if o.ExternalID != "" {
				p.ExternalID = aws.String(o.ExternalID)
			}
		})
		cfg.Credentials = aws.NewCredentialsCache(provider)
	}
	return cfg, nil
}

func strArg(args map[string]any, key string) string {
	if v, ok := args[key].(string); ok {
		return v
	}
	return ""
}

func intArg(args map[string]any, key string) (int, bool) {
	switch v := args[key].(type) {
	case float64: // JSON numbers
		return int(v), true
	case int:
		return v, true
	}
	return 0, false
}
