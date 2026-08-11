package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"syscall"

	"github.com/curlix-io/skybridge/internal/agent"
	"github.com/curlix-io/skybridge/internal/config"
	skylog "github.com/curlix-io/skybridge/internal/log"
)

// helpText covers the SKYBRIDGE_* env vars most demo/quick-start users need. It is intentionally a
// curated subset, not the exhaustive list — see internal/config/config.go and README.md#configure
// for tunnel mode, TLS, credential handoff, and session-replay options.
const helpText = `skybridge-agent — egress-only wire proxy that masks PII before it leaves the network.

All configuration is via SKYBRIDGE_* environment variables (no other flags). Common ones:

  Mode / target
    SKYBRIDGE_MODE            listener (default) | tunnel
    SKYBRIDGE_DB_TYPE         postgres (default) | mysql | mongodb
    SKYBRIDGE_LISTEN          local listen address, e.g. :15432 (default varies by DB_TYPE)
    SKYBRIDGE_UPSTREAM        upstream database host:port (required in listener mode)

  Column-name overlay (mask.Overlay — no external service needed)
    SKYBRIDGE_PII_OVERLAY         inline JSON {"column":"[redacted]"} map
    SKYBRIDGE_PII_OVERLAY_FILE    path to a YAML/JSON file with the same map (wins if both set)
    SKYBRIDGE_PII_OVERLAY_URL     control-plane endpoint to fetch + hot-swap the overlay

  Content-detection masking (mask.Remote — Presidio-compatible analyze/anonymize service)
    SKYBRIDGE_MASK_ANALYZE_URL     e.g. http://localhost:3000/analyze
    SKYBRIDGE_MASK_ANONYMIZE_URL   e.g. http://localhost:3001/anonymize
    SKYBRIDGE_MASK_ENTITIES        comma-separated Presidio entity types (default: low-cost regex set)
    SKYBRIDGE_MASK_ANONYMIZERS     JSON Presidio "anonymizers" object (per-entity strategy, e.g. partial mask)
    SKYBRIDGE_MASK_MODE            best-effort (default) | strict

Exhaustive list, including tunnel mode, TLS, and credential-exchange options:
  internal/config/config.go
  README.md#configure
`

func main() {
	help := false
	flag.BoolVar(&help, "help", false, "print SKYBRIDGE_* configuration options and exit")
	flag.BoolVar(&help, "h", false, "alias for -help")
	flag.Parse()
	if help {
		fmt.Print(helpText)
		return
	}

	cfg := config.LoadAgent()
	logger := skylog.New(os.Stderr, "skybridge-agent", skylog.ParseLevel(cfg.LogLevel))
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	var err error
	switch cfg.Mode {
	case config.ModeTunnel:
		err = agent.RunTunnel(ctx, cfg, agent.Deps{}, logger)
	default:
		err = agent.RunListener(ctx, cfg, logger)
	}
	if err != nil && ctx.Err() == nil {
		logger.Error(err.Error())
		os.Exit(1)
	}
}
