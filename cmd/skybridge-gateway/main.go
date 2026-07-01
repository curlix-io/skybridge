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
	if cfg.ControlPlaneURL != "" {
		gw.SetStore(gateway.NewHTTPStore(cfg.ControlPlaneURL, cfg.SessionPath, cfg.ControlPlaneToken))
		logger.Printf("skybridge-gateway: session recording -> %s%s", cfg.ControlPlaneURL, cfg.SessionPath)
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
		if cl.Addr == "" || cl.Target == "" {
			logger.Fatalf("client listener missing addr or target: %+v", cl)
		}
		ln, err := net.Listen("tcp", cl.Addr)
		if err != nil {
			logger.Fatal(err)
		}
		logger.Printf("skybridge-gateway: client listener %s -> target %q", cl.Addr, cl.Target)
		go func() {
			errs <- gw.ListenClients(ctx, ln, cl.Target)
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
