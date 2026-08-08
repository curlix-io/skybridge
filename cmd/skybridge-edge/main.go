package main

import (
	"context"
	"log"
	"os"
	"os/signal"
	"syscall"

	"github.com/curlix-io/skybridge/internal/agent"
	"github.com/curlix-io/skybridge/internal/config"
	"github.com/curlix-io/skybridge/internal/edge"
	"github.com/curlix-io/skybridge/internal/edge/awsexec"
	"github.com/curlix-io/skybridge/internal/edge/k8sexec"
	"github.com/curlix-io/skybridge/internal/edge/transport"
)

func main() {
	cfg := config.LoadEdge()
	config.NormalizeEdge(&cfg)
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	logger := log.Default()
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
				logger.Printf("skybridge-edge: wire proxy ended: %v", err)
			}
		}()
	}

	reg := edge.NewRegistry()
	registerQueryStudioExtras(ctx, cfg, reg, masker, logger)

	if cfg.GatewayAddr == "" {
		if cfg.WireProxyEnabled() || cfg.StudioEnabled() {
			<-ctx.Done()
			return
		}
		logger.Fatal("set SKYBRIDGE_EDGE_GATEWAY (or SKYBRIDGE_GATEWAY) to the Connector Gateway address")
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
		log.Fatal(err)
	}
}
