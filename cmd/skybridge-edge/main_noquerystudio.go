//go:build !querystudio

package main

import (
	"context"
	"log/slog"

	"github.com/curlix-io/skybridge/internal/config"
	"github.com/curlix-io/skybridge/internal/edge"
	"github.com/curlix-io/skybridge/internal/mask"
)

// registerQueryStudioExtras is a no-op in the default build: the Query Studio subsystems (db_query_*
// exec tools + the Studio Gateway dial) are only compiled in with -tags querystudio. Warn rather
// than silently doing nothing if the operator configured Studio without that tag.
func registerQueryStudioExtras(_ context.Context, cfg config.Edge, _ *edge.Registry, _ mask.Masker, logger *slog.Logger) {
	if cfg.StudioEnabled() {
		logger.Warn("SKYBRIDGE_STUDIO_GATEWAY is set but this binary was built " +
			"without -tags querystudio — Query Studio dispatch is not compiled in and will not run")
	}
}
