package trafficsampler

import (
	"context"
	"fmt"
	"log/slog"
	"time"

	"github.com/curlix-io/skybridge/internal/pathlabel/aiclassifier"
	"github.com/curlix-io/skybridge/internal/pathlabel/label"
)

// RunnerConfig configures Run. ScanIntervalSeconds falls back to a 5-minute default when <= 0 —
// classification runs off the query hot path (docs/AI_PATH_LABELLING_DESIGN.md §5.2), so this only
// needs to be frequent enough that a newly-buffered sample gets classified within one interval.
type RunnerConfig struct {
	Buffer              *Buffer
	Scanner             *aiclassifier.Scanner
	ScanIntervalSeconds int
}

const defaultScanIntervalSeconds = 300

// Run blocks scanning cfg.Buffer.Fields() through cfg.Scanner on cfg.ScanIntervalSeconds until ctx
// is done. Unlike internal/labeller.Run, this needs no DSN, no read-only credential, and no table
// discovery step of its own — cfg.Buffer already holds exactly the (ObjectID, FieldPath) pairs live
// traffic has touched, fed by whatever wire-proxy/dbquery call sites invoke Buffer.Observe. Intended
// to run as a background goroutine inside the same agent/edge process already holding the live
// database session, not as a separate role/binary.
func Run(ctx context.Context, cfg RunnerConfig, logger *slog.Logger) {
	if logger == nil {
		logger = slog.Default()
	}
	interval := cfg.ScanIntervalSeconds
	if interval <= 0 {
		interval = defaultScanIntervalSeconds
	}

	runOnce(ctx, cfg, logger)
	ticker := time.NewTicker(time.Duration(interval) * time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			runOnce(ctx, cfg, logger)
		}
	}
}

func runOnce(ctx context.Context, cfg RunnerConfig, logger *slog.Logger) {
	fields := cfg.Buffer.Fields()
	if len(fields) == 0 {
		return
	}
	n := cfg.Scanner.ScanFields(ctx, fields)
	logger.Info(fmt.Sprintf("traffic-sampler: scanned %d fields observed from live traffic, proposed %d labels (Source=%s, inert until a steward confirms)",
		len(fields), n, label.SourceProposed))
}
