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
	"github.com/curlix-io/skybridge/internal/edge/dbexec"
	"github.com/curlix-io/skybridge/internal/edge/dbquery"
	"github.com/curlix-io/skybridge/internal/edge/studiotransport"
	"github.com/curlix-io/skybridge/internal/edge/transport"
)

func main() {
	cfg := config.LoadEdge()
	config.NormalizeEdge(&cfg)
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	logger := log.Default()
	masker := agent.BuildMasker(cfg.WireProxy)
	execTargets := dbquery.MergeWireTargets(dbquery.ParseTargets(cfg.StudioTargetsJSON), cfg.WireProxy.Targets)

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

	if cfg.StudioEnabled() {
		studioCfg := studiotransport.Config{
			Target:       cfg.StudioGateway,
			TenantID:     cfg.TenantID,
			AgentID:      cfg.StudioAgentID,
			Token:        cfg.Token,
			Insecure:     cfg.Insecure,
			Reconnect:    true,
			MaxSessions:  cfg.StudioMaxSessions,
			Targets:      studiotransport.ParseTargets(cfg.StudioTargetsJSON),
			DBUser:       cfg.StudioDBUser,
			DBPassword:   cfg.StudioDBPassword,
			Masker:       masker,
			CABundlePEM:  cfg.CABundle,
			TLSDir:       cfg.StudioTLSDir,
			EnrollTarget: cfg.StudioEnrollGateway,
			EnrollToken:  cfg.StudioEnrollmentToken,
			TrustDomain:  cfg.StudioTrustDomain,
		}
		if studioCfg.TLSDir == "" {
			studioCfg.TLSDir = cfg.TLSDir
		}
		if studioCfg.EnrollToken == "" {
			studioCfg.EnrollToken = cfg.EnrollToken
		}
		go func() {
			if err := studiotransport.New(studioCfg, logger).Run(ctx); err != nil && ctx.Err() == nil {
				logger.Printf("skybridge-edge: studio gateway ended: %v", err)
			}
		}()
	}

	if cfg.GatewayAddr == "" {
		if cfg.WireProxyEnabled() || cfg.StudioEnabled() {
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
	dbexec.Register(reg, dbexec.Options{
		Targets:          execTargets,
		FallbackUser:     cfg.StudioDBUser,
		FallbackPassword: cfg.StudioDBPassword,
		Masker:           masker,
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
