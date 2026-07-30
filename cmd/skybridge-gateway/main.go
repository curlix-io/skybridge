package main

import (
	"context"
	"errors"
	"log"
	"net"
	"os"
	"os/signal"
	"syscall"

	"github.com/curlix-io/skybridge/internal/config"
	"github.com/curlix-io/skybridge/internal/gateway"
)

func main() {
	cfg := config.LoadGateway()
	logger := log.Default()

	gw := gateway.New(cfg.AuthToken, logger)
	gw.SetRequireOrgID(cfg.RequireOrgID)
	if lim := gateway.NewConnRateLimiter(cfg.ClientConnPerMin, cfg.OrgConnPerMin); lim != nil {
		gw.SetConnRateLimiter(lim)
		logger.Printf("skybridge-gateway: client conn limits ip=%d/min org=%d/min", cfg.ClientConnPerMin, cfg.OrgConnPerMin)
	}
	if cfg.ControlPlaneURL != "" {
		gw.SetStore(gateway.NewHTTPStore(cfg.ControlPlaneURL, cfg.SessionPath, cfg.ControlPlaneToken))
		gw.SetWireAdmitter(gateway.NewHTTPWireAdmitter(cfg.ControlPlaneURL, cfg.WireAdmitPath, cfg.ControlPlaneToken))
		gw.SetTargetResolver(gateway.NewHTTPTargetResolver(cfg.ControlPlaneURL, cfg.WireTargetPath, cfg.ControlPlaneToken))
		logger.Printf("skybridge-gateway: session recording -> %s%s", cfg.ControlPlaneURL, cfg.SessionPath)
		logger.Printf("skybridge-gateway: wire IP admission -> %s%s", cfg.ControlPlaneURL, cfg.WireAdmitPath)
		logger.Printf("skybridge-gateway: wire target resolution -> %s%s", cfg.ControlPlaneURL, cfg.WireTargetPath)
	} else {
		logger.Printf("skybridge-gateway: WARNING: no SKYBRIDGE_GW_CONTROL_PLANE_URL — target resolution will fail closed for all client connections")
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	errs := make(chan error, 1+len(cfg.Clients))

	agentLn, err := net.Listen("tcp", cfg.AgentListen)
	if err != nil {
		logger.Fatal(err)
	}
	logger.Printf("skybridge-gateway: agent endpoint %s", cfg.AgentListen)
	go func() { errs <- gw.ListenAgents(ctx, agentLn) }()

	for _, cl := range cfg.Clients {
		cl := cl
		if cl.Addr == "" || cl.Target == "" || cl.OrgID == "" {
			logger.Fatalf("client listener missing addr/org_id/target: %+v", cl)
		}
		ln, err := net.Listen("tcp", cl.Addr)
		if err != nil {
			logger.Fatal(err)
		}
		if cfg.ClientProxyProtocol {
			ln = gateway.WrapProxyProtocol(ln, 0)
			logger.Printf("skybridge-gateway: client listener %s expects PROXY protocol (NLB client-IP passthrough)", cl.Addr)
		}
		logger.Printf("skybridge-gateway: client listener %s -> org %q target %q", cl.Addr, cl.OrgID, cl.Target)
		go func() {
			errs <- gw.ListenClients(ctx, ln, cl.OrgID, cl.Target)
		}()
	}

	if len(cfg.Clients) == 0 {
		logger.Printf("skybridge-gateway: WARNING: no SKYBRIDGE_GW_CLIENTS configured")
	}

	select {
	case <-ctx.Done():
	case err := <-errs:
		if err != nil && !errors.Is(err, net.ErrClosed) && ctx.Err() == nil {
			logger.Fatal(err)
		}
	}
}
