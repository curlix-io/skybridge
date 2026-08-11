package main

import (
	"context"
	"log/slog"
	"os"
	"os/signal"
	"syscall"

	"github.com/curlix-io/skybridge/internal/agent"
	"github.com/curlix-io/skybridge/internal/config"
	"github.com/curlix-io/skybridge/internal/edge"
	"github.com/curlix-io/skybridge/internal/edge/awsexec"
	"github.com/curlix-io/skybridge/internal/edge/dbexec"
	"github.com/curlix-io/skybridge/internal/edge/dbquery"
	"github.com/curlix-io/skybridge/internal/edge/k8sexec"
	"github.com/curlix-io/skybridge/internal/edge/k8stoken"
	"github.com/curlix-io/skybridge/internal/edge/studiotransport"
	"github.com/curlix-io/skybridge/internal/edge/transport"
	skylog "github.com/curlix-io/skybridge/internal/log"
	"github.com/curlix-io/skybridge/internal/mask"
)

func runEdge(args []string) {
	cfg := config.LoadEdge()
	config.NormalizeEdge(&cfg)
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	logger := skylog.New(os.Stderr, "skybridge-edge", skylog.ParseLevel(cfg.LogLevel))
	masker := agent.BuildMasker(cfg.WireProxy)

	if cfg.WireProxyEnabled() {
		wp := cfg.WireProxy
		go func() {
			var err error
			switch wp.Mode {
			case config.ModeTunnel:
				err = agent.RunTunnel(ctx, wp, agent.Deps{}, logger)
			default:
				err = agent.RunListener(ctx, wp, logger)
			}
			if err != nil && ctx.Err() == nil {
				logger.Error("wire proxy ended", "error", err)
			}
		}()
	}

	reg := edge.NewRegistry()
	registerQueryStudio(ctx, cfg, reg, masker, logger)

	if cfg.GatewayAddr == "" {
		if cfg.WireProxyEnabled() || cfg.StudioEnabled() {
			<-ctx.Done()
			return
		}
		logger.Error("set SKYBRIDGE_EDGE_GATEWAY (or SKYBRIDGE_GATEWAY) to the Connector Gateway address")
		os.Exit(1)
	}

	awsexec.Register(reg, awsexec.Options{
		Region:        cfg.AWSRegion,
		AssumeRoleARN: cfg.AWSAssumeRoleARN,
		ExternalID:    cfg.AWSExternalID,
		AWSBinary:     cfg.AWSBinary,
	})
	// Kubernetes access is opt-in: only registered when a kubeconfig/context is configured
	// (external-connector mode — see docs/design/kubernetes-access-broker.md §8.2. In-cluster
	// deployment with a bound ServiceAccount needs no kubeconfig and can enable this the same way
	// once that story is scoped).
	if cfg.K8sKubeconfig != "" || cfg.K8sContext != "" {
		k8sexec.Register(reg, k8sexec.Options{
			Kubeconfig: cfg.K8sKubeconfig,
			Context:    cfg.K8sContext,
			KubectlBin: cfg.K8sBinary,
		})
		// Phase 2 (docs/design/kubernetes-access-broker.md §4/§7): per-session TokenRequest
		// minting, same opt-in gate as k8sexec above — reuses the same kubeconfig/context/binary,
		// no new config surface.
		k8stoken.Register(reg, k8stoken.Options{
			Kubeconfig: cfg.K8sKubeconfig,
			Context:    cfg.K8sContext,
			KubectlBin: cfg.K8sBinary,
		})
	}

	client := transport.New(transport.Config{
		Target:            cfg.GatewayAddr,
		TenantID:          cfg.TenantID,
		ConnectorID:       cfg.EdgeID,
		Token:             cfg.Token,
		Insecure:          cfg.Insecure,
		Reconnect:         true,
		CABundlePEM:       cfg.CABundle,
		TLSDir:            cfg.TLSDir,
		IdentitySecretARN: cfg.IdentitySecretARN,
		EnrollTarget:      cfg.EnrollTarget,
		EnrollToken:       cfg.EnrollToken,
		TrustDomain:       cfg.TrustDomain,
	}, reg, logger)

	if err := client.Run(ctx); err != nil && ctx.Err() == nil {
		logger.Error(err.Error())
		os.Exit(1)
	}
}

// registerQueryStudio wires up the Query Studio subsystems: the db_query_* one-shot exec tools
// (registered on reg, dispatched over the connector-gateway transport already running above) and
// the second, independent Studio Gateway dial for Query Studio's own dispatch. Always compiled in;
// dormant unless cfg.StudioEnabled() (SKYBRIDGE_STUDIO_GATEWAY set).
func registerQueryStudio(ctx context.Context, cfg config.Edge, reg *edge.Registry, masker mask.Masker, logger *slog.Logger) {
	execTargets := dbquery.MergeWireTargets(dbquery.ParseTargets(cfg.StudioTargetsJSON), cfg.WireProxy.Targets)
	dbexec.Register(reg, dbexec.Options{
		Targets:          execTargets,
		FallbackUser:     cfg.StudioDBUser,
		FallbackPassword: cfg.StudioDBPassword,
		Masker:           masker,
		OrgID:            cfg.TenantID,
	})
	dbexec.RegisterMigration(reg, dbexec.MigrationOptions{
		Targets:          execTargets,
		FallbackUser:     cfg.StudioDBUser,
		FallbackPassword: cfg.StudioDBPassword,
	})

	if !cfg.StudioEnabled() {
		return
	}
	studioCfg := studiotransport.Config{
		Target:            cfg.StudioGateway,
		TenantID:          cfg.TenantID,
		AgentID:           cfg.StudioAgentID,
		Token:             cfg.Token,
		Insecure:          cfg.Insecure,
		Reconnect:         true,
		MaxSessions:       cfg.StudioMaxSessions,
		Targets:           studiotransport.ParseTargets(cfg.StudioTargetsJSON),
		DBUser:            cfg.StudioDBUser,
		DBPassword:        cfg.StudioDBPassword,
		Masker:            masker,
		CABundlePEM:       cfg.CABundle,
		TLSDir:            cfg.StudioTLSDir,
		IdentitySecretARN: cfg.StudioIdentitySecretARN,
		EnrollTarget:      cfg.StudioEnrollGateway,
		EnrollToken:       cfg.StudioEnrollmentToken,
		TrustDomain:       cfg.StudioTrustDomain,
	}
	if studioCfg.TLSDir == "" {
		studioCfg.TLSDir = cfg.TLSDir
	}
	if studioCfg.EnrollToken == "" {
		studioCfg.EnrollToken = cfg.EnrollToken
	}
	go func() {
		if err := studiotransport.New(studioCfg, logger).Run(ctx); err != nil && ctx.Err() == nil {
			logger.Error("studio gateway ended", "error", err)
		}
	}()
}
