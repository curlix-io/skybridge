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
	"sort"
	"time"

	_ "github.com/go-sql-driver/mysql"
	_ "github.com/jackc/pgx/v5/stdlib"
	_ "github.com/snowflakedb/gosnowflake"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"

	"github.com/curlix-io/skybridge/internal/config"
	"github.com/curlix-io/skybridge/internal/pathlabel/aiclassifier"
	"github.com/curlix-io/skybridge/internal/pathlabel/label"
	"github.com/curlix-io/skybridge/internal/pathlabel/mongosampler"
	"github.com/curlix-io/skybridge/internal/pathlabel/remotestore"
	"github.com/curlix-io/skybridge/internal/pathlabel/sqlsampler"
)

// sampleLister is what runOnce needs from a sampler beyond aiclassifier.Sampler's own Sample
// method: discovering which tables/collections exist and which fields under each are worth
// sampling this cycle. Both sqlsampler.Sampler (real information_schema catalog lookups) and
// mongosampler.Sampler (ListTables via the driver's own catalog command; ListColumns via a
// best-effort field-discovery scan, since Mongo has no fixed schema to query) implement it under
// these same names so runOnce doesn't need to branch on db type.
type sampleLister interface {
	ListColumns(ctx context.Context, schema, table string) ([]string, error)
	// ListTables discovers every table/collection in schema, used when cfg.Tables is empty
	// (SKYBRIDGE_LABELLER_TABLES unset) so this job doesn't require an operator-maintained table
	// list to find new tables/collections as they're created.
	ListTables(ctx context.Context, schema string) ([]string, error)
}

// scheduler bounds how many tables/collections runOnce scans per cycle and skips ones scanned too
// recently, so a schema with tens of thousands of tables (a real deployment scale once Tables is
// discovered dynamically rather than an operator-maintained list, per config.Labeller.Tables' doc
// comment) doesn't fan out into a proportional number of LLM Classify calls every cycle. State is
// in-memory only, scoped to one Run call — a process restart just resets the round-robin/rescan
// clock, which is a scheduling optimization losing its head start, not a correctness problem; the
// next cycle simply treats every object as never-scanned again, same as this job's first-ever run.
type scheduler struct {
	lastScanned map[string]time.Time
}

func newScheduler() *scheduler {
	return &scheduler{lastScanned: make(map[string]time.Time)}
}

// selectObjects returns up to maxObjects of candidates: candidates scanned within rescanInterval of
// now are dropped first (skip-if-recently-scanned; rescanInterval <= 0 disables this), then the
// remainder is ordered least-recently-scanned first (a never-scanned object's zero time.Time always
// sorts first) and capped at maxObjects (maxObjects <= 0 means unlimited). This ordering is what
// makes repeated calls round-robin through a large candidate set: whichever objects this cycle
// skips due to the cap are exactly the ones with the most recent lastScanned, so they naturally sort
// last next cycle too, behind everything not yet covered.
func (s *scheduler) selectObjects(candidates []string, maxObjects int, rescanInterval time.Duration, now time.Time) []string {
	eligible := make([]string, 0, len(candidates))
	for _, c := range candidates {
		if last, ok := s.lastScanned[c]; ok && rescanInterval > 0 && now.Sub(last) < rescanInterval {
			continue
		}
		eligible = append(eligible, c)
	}
	sort.Slice(eligible, func(i, j int) bool {
		return s.lastScanned[eligible[i]].Before(s.lastScanned[eligible[j]])
	})
	if maxObjects > 0 && len(eligible) > maxObjects {
		eligible = eligible[:maxObjects]
	}
	return eligible
}

// markScanned records that every object in objects was scanned at now, so the next selectObjects
// call skips/deprioritizes them per rescanInterval/round-robin ordering above.
func (s *scheduler) markScanned(objects []string, now time.Time) {
	for _, o := range objects {
		s.lastScanned[o] = now
	}
}

// sqlDriverName maps config.Labeller.DBType to the database/sql driver name registered by this
// package's blank imports above. Mongo has no database/sql driver — it's handled by a separate
// path in Run, never reaching this function.
func sqlDriverName(dbType string) (string, error) {
	switch dbType {
	case "postgres", "postgresql":
		return "pgx", nil
	case "mysql":
		return "mysql", nil
	case "snowflake":
		return "snowflake", nil
	default:
		return "", fmt.Errorf("labeller: unsupported SKYBRIDGE_LABELLER_DB_TYPE %q (postgres, mysql, snowflake, or mongo)", dbType)
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

	var sampler sampleLister
	var aiSampler aiclassifier.Sampler
	if normalizeDriver(cfg.DBType) == "mongo" {
		client, err := mongo.Connect(ctx, options.Client().ApplyURI(cfg.DSN))
		if err != nil {
			return fmt.Errorf("labeller: opening sampling connection: %w", err)
		}
		defer func() { _ = client.Disconnect(context.Background()) }()
		ms := mongosampler.New(client)
		sampler, aiSampler = ms, ms
	} else {
		driverName, err := sqlDriverName(cfg.DBType)
		if err != nil {
			return err
		}
		db, err := sql.Open(driverName, cfg.DSN)
		if err != nil {
			return fmt.Errorf("labeller: opening sampling connection: %w", err)
		}
		defer db.Close()
		ss := sqlsampler.New(db, cfg.DBType)
		sampler, aiSampler = ss, ss
	}

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
		Sampler:    aiSampler,
		Store:      store,
		MaxSamples: cfg.MaxSamplesPerField,
	})

	logger.Printf("skybridge-labeller: starting, db_type=%s database=%s tables=%v scan_interval=%ds max_objects_per_scan=%d rescan_interval=%ds",
		cfg.DBType, cfg.Database, cfg.Tables, cfg.ScanIntervalSeconds, cfg.MaxObjectsPerScan, cfg.RescanIntervalSeconds)

	sched := newScheduler()
	runOnce(ctx, cfg, sampler, scanner, sched, logger)
	ticker := time.NewTicker(time.Duration(cfg.ScanIntervalSeconds) * time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return nil
		case <-ticker.C:
			runOnce(ctx, cfg, sampler, scanner, sched, logger)
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
	case cfg.LLMEndpoint == "":
		return fmt.Errorf("labeller: SKYBRIDGE_LABELLER_LLM_ENDPOINT is required")
	case len(cfg.LLMCategories) == 0:
		return fmt.Errorf("labeller: SKYBRIDGE_LABELLER_LLM_CATEGORIES is required")
	case cfg.PathLabelURL == "":
		return fmt.Errorf("labeller: SKYBRIDGE_PATH_LABEL_URL is required (this job only ever proposes through it)")
	}
	return nil
}

// runOnce resolves this cycle's table/collection list (cfg.Tables if set, otherwise a live
// sampler.ListTables discovery), asks sched to bound/round-robin that list down to
// cfg.MaxObjectsPerScan eligible objects, then discovers each selected object's columns and runs
// one classification pass over all of them. A per-table column-listing failure is logged and
// skipped — the same "one bad object never blocks the rest of the scan" posture
// aiclassifier.Scanner already applies per-field.
func runOnce(ctx context.Context, cfg config.Labeller, sampler sampleLister, scanner *aiclassifier.Scanner, sched *scheduler, logger *log.Logger) {
	tables := cfg.Tables
	if len(tables) == 0 {
		discovered, err := sampler.ListTables(ctx, cfg.Database)
		if err != nil {
			logger.Printf("skybridge-labeller: discovering tables for database %s: %v (skipping this cycle)", cfg.Database, err)
			return
		}
		tables = discovered
	}

	now := time.Now()
	selected := sched.selectObjects(tables, cfg.MaxObjectsPerScan, time.Duration(cfg.RescanIntervalSeconds)*time.Second, now)

	var fields []aiclassifier.Field
	for _, table := range selected {
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
	sched.markScanned(selected, now)

	n := scanner.ScanFields(ctx, fields)
	logger.Printf("skybridge-labeller: scanned %d/%d tables (%d fields), proposed %d labels (Source=%s, inert until a steward confirms)",
		len(selected), len(tables), len(fields), n, label.SourceProposed)
}

// normalizeDriver matches internal/edge/dbquery's objectID convention ("postgres"/"mongo", not
// "postgresql"/"mongodb") so ObjectIDs this job proposes line up with ObjectIDs the wire
// proxy/dbquery resolve for the same table/collection.
func normalizeDriver(dbType string) string {
	switch dbType {
	case "postgresql":
		return "postgres"
	case "mongodb":
		return "mongo"
	default:
		return dbType
	}
}
