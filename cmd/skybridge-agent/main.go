package main

import (
	"context"
	"log"
	"os"
	"os/signal"
	"syscall"

	"github.com/curlix-io/skybridge/internal/agent"
	"github.com/curlix-io/skybridge/internal/config"
)

func main() {
	cfg := config.LoadAgent()
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	var err error
	switch cfg.Mode {
	case config.ModeTunnel:
		err = agent.RunTunnel(ctx, cfg, agent.Deps{}, nil)
	default:
		err = agent.RunListener(ctx, cfg, nil)
	}
	if err != nil && ctx.Err() == nil {
		log.Fatal(err)
	}
}
