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
	"github.com/curlix-io/skybridge/internal/edge/transport"
)

func main() {
	cfg := config.LoadEdge()
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	logger := log.Default()

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

	if cfg.GatewayAddr == "" {
		if cfg.WireProxyEnabled() {
			<-ctx.Done()
			return
		}
		logger.Fatal("set SKYBRIDGE_EDGE_GATEWAY (or SKYBRIDGE_GATEWAY) to the Connector Gateway address")
	}

	reg := edge.NewRegistry()
	awsexec.Register(reg, awsexec.Options{
		Region:        cfg.AWSRegion,
		AssumeRoleARN: cfg.AWSAssumeRoleARN,
		ExternalID:    cfg.AWSExternalID,
		AWSBinary:     cfg.AWSBinary,
	})

	client := transport.New(transport.Config{
		Target:       cfg.GatewayAddr,
		TenantID:     cfg.TenantID,
		ConnectorID:  cfg.EdgeID,
		Token:        cfg.Token,
		Insecure:     cfg.Insecure,
		Reconnect:    true,
		CABundlePEM:  cfg.CABundle,
		TLSDir:       cfg.TLSDir,
		EnrollTarget: cfg.EnrollTarget,
		EnrollToken:  cfg.EnrollToken,
		TrustDomain:  cfg.TrustDomain,
	}, reg, logger)

	if err := client.Run(ctx); err != nil && ctx.Err() == nil {
		log.Fatal(err)
	}
}
