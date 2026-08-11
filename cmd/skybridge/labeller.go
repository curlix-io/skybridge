package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"syscall"

	"github.com/curlix-io/skybridge/internal/config"
	"github.com/curlix-io/skybridge/internal/labeller"
	skylog "github.com/curlix-io/skybridge/internal/log"
)

// labellerHelpText covers the SKYBRIDGE_* env vars this role reads. See
// docs/AI_PATH_LABELLING_DESIGN.md for the design and internal/config/config.go's Labeller struct
// for the exhaustive, always-up-to-date list.
const labellerHelpText = `skybridge labeller — periodic AI-based path-label scan job (docs/AI_PATH_LABELLING_DESIGN.md).

Samples a bounded number of rows per configured table column, classifies each via an LLM, and
proposes any confident result to the control plane as label.SourceProposed — it never redacts
anything itself; a proposal only takes effect once a steward confirms it (PathOverlay's existing
confirm gate is untouched by this role).

All configuration is via SKYBRIDGE_* environment variables (no other flags):

  Required
    SKYBRIDGE_ORG_ID                    tenant this scan job proposes labels for
    SKYBRIDGE_LABELLER_DB_TYPE          postgres (default) | mysql
    SKYBRIDGE_LABELLER_DSN              read-only credential for the database to sample — a
                                         dedicated credential, never a live client session's own
    SKYBRIDGE_LABELLER_DATABASE         logical database name (embedded in the resulting ObjectID)
    SKYBRIDGE_LABELLER_TABLES           comma-separated table list to scan every cycle
    SKYBRIDGE_LABELLER_LLM_ENDPOINT     LLM completion API this job prompts (POST {prompt} ->
                                         {category, profile, confidence, rationale})
    SKYBRIDGE_LABELLER_LLM_CATEGORIES   comma-separated taxonomy the model is constrained to
    SKYBRIDGE_PATH_LABEL_URL            control-plane pii-path-labels endpoint this job proposes to

  Optional
    SKYBRIDGE_LABELLER_LLM_API_KEY              sent as a Bearer token to LLM_ENDPOINT
    SKYBRIDGE_LABELLER_LLM_MIN_CONFIDENCE       default 0.5 — discard model responses below this
    SKYBRIDGE_LABELLER_MAX_SAMPLES               sample values requested per column per cycle
    SKYBRIDGE_LABELLER_SCAN_INTERVAL_SECONDS     default 3600, floored at 300
    SKYBRIDGE_TOKEN / SKYBRIDGE_PATH_LABEL_TOKEN  bearer token for the control-plane calls above

Full field-level documentation: internal/config/config.go's Labeller struct.
`

func runLabeller(args []string) {
	fs := flag.NewFlagSet("labeller", flag.ExitOnError)
	help := false
	fs.BoolVar(&help, "help", false, "print SKYBRIDGE_* configuration options and exit")
	fs.BoolVar(&help, "h", false, "alias for -help")
	fs.Parse(args)
	if help {
		fmt.Print(labellerHelpText)
		return
	}

	cfg := config.LoadLabeller()
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	logger := skylog.New(os.Stderr, "skybridge-labeller", skylog.ParseLevel(cfg.LogLevel))
	if err := labeller.Run(ctx, cfg, logger); err != nil && ctx.Err() == nil {
		logger.Error(err.Error())
		os.Exit(1)
	}
}
