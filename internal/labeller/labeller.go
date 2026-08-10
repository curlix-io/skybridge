// Package labeller runs skybridge-labeller's periodic AI-based path-label scan job: for each
// configured table, discover its columns, sample values, classify them via
// internal/pathlabel/aiclassifier, and push any confident proposal to the control plane via
// internal/pathlabel/remotestore — all as label.SourceProposed, never redacting anything on its
// own. See docs/AI_PATH_LABELLING_DESIGN.md for the full design this implements.
package labeller

import (
	"context"
	"database/sql"
	"fmt"
	"log"
	"time"

	_ "github.com/go-sql-driver/mysql"
	_ "github.com/jackc/pgx/v5/stdlib"

	"github.com/curlix-io/skybridge/internal/config"
	"github.com/curlix-io/skybridge/internal/pathlabel/aiclassifier"
	"github.com/curlix-io/skybridge/internal/pathlabel/label"
	"github.com/curlix-io/skybridge/internal/pathlabel/remotestore"
	"github.com/curlix-io/skybridge/internal/pathlabel/sqlsampler"
)

// sqlDriverName maps config.Labeller.DBType to the database/sql driver name registered by this
// package's blank imports above.
func sqlDriverName(dbType string) (string, error) {
	switch dbType {
	case "postgres", "postgresql":
		return "pgx", nil
	case "mysql":
		return "mysql", nil
	default:
		return "", fmt.Errorf("labeller: unsupported SKYBRIDGE_LABELLER_DB_TYPE %q (postgres or mysql)", dbType)
	}
}

// Run validates cfg, opens the sampling connection, and blocks running scan cycles on
// cfg.ScanIntervalSeconds until ctx is done. Returns an error only for a startup-time
// configuration problem (bad DSN, missing required field) — a per-cycle sampling/classification
// failure is logged and the loop continues, matching mask.Remote's best-effort philosophy
// (docs/AI_PATH_LABELLING_DESIGN.md §5.5).
func Run(ctx context.Context, cfg config.Labeller, logger *log.Logger) error {
	if logger == nil {
		logger = log.Default()
	}
	if err := validate(cfg); err != nil {
		return err
	}

	driverName, err := sqlDriverName(cfg.DBType)
	if err != nil {
		return err
	}
	db, err := sql.Open(driverName, cfg.DSN)
	if err != nil {
		return fmt.Errorf("labeller: opening sampling connection: %w", err)
	}
	defer db.Close()

	sampler := sqlsampler.New(db, cfg.DBType)
	classifier := aiclassifier.NewLLM(aiclassifier.LLMConfig{
		Endpoint:      cfg.LLMEndpoint,
		APIKey:        cfg.LLMAPIKey,
		Categories:    cfg.LLMCategories,
		MinConfidence: cfg.LLMMinConfidence,
	})
	store := remotestore.New(config.Agent{
		OrgID:                cfg.OrgID,
		PathLabelURL:         cfg.PathLabelURL,
		PathLabelToken:       cfg.PathLabelToken,
		PathLabelPollSeconds: cfg.PathLabelPollSeconds,
		PathLabelPushSeconds: cfg.PathLabelPushSeconds,
	}, logger)
	store.Start(ctx)

	scanner := aiclassifier.NewScanner(aiclassifier.ScannerConfig{
		Classifier: classifier,
		Sampler:    sampler,
		Store:      store,
		MaxSamples: cfg.MaxSamplesPerField,
	})

	logger.Printf("skybridge-labeller: starting, db_type=%s database=%s tables=%v scan_interval=%ds",
		cfg.DBType, cfg.Database, cfg.Tables, cfg.ScanIntervalSeconds)

	runOnce(ctx, cfg, sampler, scanner, logger)
	ticker := time.NewTicker(time.Duration(cfg.ScanIntervalSeconds) * time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return nil
		case <-ticker.C:
			runOnce(ctx, cfg, sampler, scanner, logger)
		}
	}
}

func validate(cfg config.Labeller) error {
	switch {
	case cfg.OrgID == "":
		return fmt.Errorf("labeller: SKYBRIDGE_ORG_ID is required")
	case cfg.DSN == "":
		return fmt.Errorf("labeller: SKYBRIDGE_LABELLER_DSN is required")
	case cfg.Database == "":
		return fmt.Errorf("labeller: SKYBRIDGE_LABELLER_DATABASE is required")
	case len(cfg.Tables) == 0:
		return fmt.Errorf("labeller: SKYBRIDGE_LABELLER_TABLES is required (comma-separated table list)")
	case cfg.LLMEndpoint == "":
		return fmt.Errorf("labeller: SKYBRIDGE_LABELLER_LLM_ENDPOINT is required")
	case len(cfg.LLMCategories) == 0:
		return fmt.Errorf("labeller: SKYBRIDGE_LABELLER_LLM_CATEGORIES is required")
	case cfg.PathLabelURL == "":
		return fmt.Errorf("labeller: SKYBRIDGE_PATH_LABEL_URL is required (this job only ever proposes through it)")
	}
	return nil
}

// runOnce discovers every configured table's columns and runs one classification pass over all of
// them. A per-table column-listing failure is logged and skipped — the same "one bad object never
// blocks the rest of the scan" posture aiclassifier.Scanner already applies per-field.
func runOnce(ctx context.Context, cfg config.Labeller, sampler *sqlsampler.Sampler, scanner *aiclassifier.Scanner, logger *log.Logger) {
	var fields []aiclassifier.Field
	for _, table := range cfg.Tables {
		objID := fmt.Sprintf("%s:%s:%s:%s", cfg.OrgID, normalizeDriver(cfg.DBType), cfg.Database, table)
		cols, err := sampler.ListColumns(ctx, cfg.Database, table)
		if err != nil {
			logger.Printf("skybridge-labeller: listing columns for %s: %v (skipping this table this cycle)", objID, err)
			continue
		}
		for _, col := range cols {
			fields = append(fields, aiclassifier.Field{ObjectID: objID, FieldPath: col})
		}
	}

	n := scanner.ScanFields(ctx, fields)
	logger.Printf("skybridge-labeller: scanned %d fields, proposed %d labels (Source=%s, inert until a steward confirms)",
		len(fields), n, label.SourceProposed)
}

// normalizeDriver matches internal/edge/dbquery's objectID convention ("postgres", not
// "postgresql") so ObjectIDs this job proposes line up with ObjectIDs the wire proxy/dbquery
// resolve for the same table.
func normalizeDriver(dbType string) string {
	if dbType == "postgresql" {
		return "postgres"
	}
	return dbType
}
