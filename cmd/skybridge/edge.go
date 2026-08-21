package main

import (
	"context"
	"flag"
	"fmt"
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

// edgeHelpText covers the SKYBRIDGE_* env vars most customers need. It is intentionally a
// curated subset, not the exhaustive list — see internal/config/config.go's Edge struct and
// README.md#the-edge-role for AWS/k8s tool exec, Studio dispatch, and the co-located wire proxy's
// full option set (same vars as `skybridge agent`, since WireProxy reuses config.LoadAgent()).
const edgeHelpText = `skybridge edge — unified edge: call-home to a Connector Gateway, local AWS/k8s
tool exec, optional Query Studio dispatch, and an optional co-located DB wire proxy.

All configuration is via SKYBRIDGE_* environment variables (no other flags). Common ones:

  Quick start
    SKYBRIDGE_KEY               one DSN replacing the vars below (curlix://org:token@host?...)

  Call-home
    SKYBRIDGE_EDGE_GATEWAY      Connector Gateway host:port (e.g. <nlb-dns>:7100)
    SKYBRIDGE_ORG_ID            tenant id
    SKYBRIDGE_EDGE_ID           stable instance id (default "skybridge-edge")
    SKYBRIDGE_ENROLL_GATEWAY    enrollment host:port (typically <nlb-dns>:7101)
    SKYBRIDGE_ENROLLMENT_TOKEN  one-time token, first run only
    SKYBRIDGE_CA_BUNDLE_PEM     SaaS CA public cert (mTLS)
    SKYBRIDGE_IAM_AUTH          mint the enroll token from the edge's ambient AWS identity
                                instead of SKYBRIDGE_ENROLLMENT_TOKEN — safe on every restart
    SKYBRIDGE_IAM_ENROLL_URL    control-plane origin for SKYBRIDGE_IAM_AUTH's enroll-token mint

  AWS / Kubernetes tool exec
    SKYBRIDGE_AWS_REGION        region for local AWS reads
    SKYBRIDGE_K8S_KUBECONFIG    kubeconfig path (external-connector mode; opt-in)

  Query Studio dispatch (second outbound stream, :7200/:7201)
    SKYBRIDGE_STUDIO_GATEWAY         Studio Gateway host:port
    SKYBRIDGE_STUDIO_ENROLL_GATEWAY  Studio enrollment host:port

  Co-located DB wire proxy (same process, same SKYBRIDGE_* vars as "skybridge agent" --help)
    SKYBRIDGE_UPSTREAM          upstream database host:port — set this to also run the wire proxy

Exhaustive list: internal/config/config.go (Edge struct), README.md#the-edge-role.
`

// logConnectivitySummary logs, once at startup, exactly which host each configured outbound
// channel resolved to and whether a CA bundle is set for it -- never the CA/token contents
// themselves, only presence and target. This process can dial up to three independent gateways
// (connector, Studio, wire-proxy tunnel) that each need their OWN correct host+CA pairing; a
// misconfiguration where one channel's CA bundle is used to validate a DIFFERENT channel's host
// produces an identical-looking "x509: certificate signed by unknown authority" regardless of
// which channel is actually broken. Printing the resolved wiring up front turns "which of these
// three hosts is actually wrong" from a debugging session into a one-line read.
func logConnectivitySummary(cfg config.Edge, logger *slog.Logger) {
	logger.Info("connector-gateway call-home",
		"gateway_addr", orNotConfigured(cfg.GatewayAddr),
		"org_id", cfg.TenantID,
		"edge_id", cfg.EdgeID,
		"bearer_mode", cfg.ReusableConnectorKeyConfigured(),
		"ca_bundle_configured", len(cfg.CABundle) > 0,
	)
	if cfg.StudioEnabled() {
		logger.Info("query studio call-home",
			"gateway_addr", orNotConfigured(cfg.StudioGateway),
			"agent_id", cfg.StudioAgentID,
			"bearer_mode", cfg.ReusableConnectorKeyConfigured(),
			"ca_bundle_configured", len(cfg.CABundle) > 0,
		)
	}
	if cfg.WireProxyEnabled() {
		wp := cfg.WireProxy
		logger.Info("wire-proxy tunnel",
			"mode", wp.Mode,
			"gateway_addr", orNotConfigured(wp.GatewayAddr),
			"bearer_mode", wp.ReusableConnectorKeyConfigured(),
			"ca_bundle_configured", len(wp.CABundle) > 0,
			"wire_mtls_ca_bundle_configured", len(wp.WireMtlsCABundlePEM) > 0,
		)
	}
}

func orNotConfigured(s string) string {
	if s == "" {
		return "(not configured)"
	}
	return s
}

func runEdge(args []string) {
	fs := flag.NewFlagSet("edge", flag.ExitOnError)
	help := false
	fs.BoolVar(&help, "help", false, "print SKYBRIDGE_* configuration options and exit")
	fs.BoolVar(&help, "h", false, "alias for -help")
	fs.Parse(args)
	if help {
		fmt.Print(edgeHelpText)
		return
	}

	cfg := config.LoadEdge()
	config.NormalizeEdge(&cfg)
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	logger := skylog.New(os.Stderr, "skybridge-edge", skylog.ParseLevel(cfg.LogLevel))
	logConnectivitySummary(cfg, logger)
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

	// Standalone in-cluster K8s API proxy listener — independent of WireProxy.Mode above (can run
	// alongside a DB wire tunnel, or on its own with no WireProxy config at all). See
	// docs/design/kubernetes-access-broker.md §11.1.
	if cfg.WireProxy.K8sAPIListenAddr != "" {
		go func() {
			if err := agent.RunK8sAPIListener(ctx, cfg.WireProxy, logger); err != nil && ctx.Err() == nil {
				logger.Error("k8s API listener ended", "error", err)
			}
		}()
	}

	reg := edge.NewRegistry()
	execTargets := dbquery.MergeWireTargets(dbquery.ParseTargets(cfg.StudioTargetsJSON), cfg.WireProxy.Targets)
	registerQueryStudio(ctx, cfg, execTargets, reg, masker, logger)

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
		ForceBearer:       cfg.ReusableConnectorKeyConfigured(),
		CABundlePEM:       cfg.CABundle,
		TLSDir:            cfg.TLSDir,
		IdentitySecretARN: cfg.IdentitySecretARN,
		EnrollTarget:      cfg.EnrollTarget,
		EnrollToken:       cfg.EnrollToken,
		TrustDomain:       cfg.TrustDomain,
		Targets:           execTargets,
		IamAuthEnabled:    cfg.IamAuthEnabled,
		IamEnrollURL:      cfg.IamEnrollURL,
		SpireSocketPath:   cfg.WireProxy.SpireSocketPath,
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
func registerQueryStudio(ctx context.Context, cfg config.Edge, execTargets []dbquery.Target, reg *edge.Registry, masker mask.Masker, logger *slog.Logger) {
	dbexec.Register(reg, dbexec.Options{
		Targets:          execTargets,
		FallbackUser:     cfg.StudioDBUser,
		FallbackPassword: cfg.StudioDBPassword,
		Masker:           masker,
		OrgID:            cfg.TenantID,
		Neo4jStaticURI:   cfg.AssetInventoryNeo4jURI,
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
		ForceBearer:       cfg.ReusableConnectorKeyConfigured(),
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
		IamAuthEnabled:    cfg.IamAuthEnabled,
		IamEnrollURL:      cfg.IamEnrollURL,
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
