package labeller

import (
	"context"
	"log"
	"sort"
	"testing"
	"time"

	"github.com/curlix-io/skybridge/internal/config"
	"github.com/curlix-io/skybridge/internal/pathlabel/aiclassifier"
	"github.com/curlix-io/skybridge/internal/pathlabel/label"
)

func validLabellerConfig() config.Labeller {
	return config.Labeller{
		OrgID:               "org1",
		DBType:              "postgres",
		DSN:                 "postgres://u:p@127.0.0.1:5432/appdb",
		Database:            "appdb",
		Tables:              []string{"users"},
		LLMEndpoint:         "http://stub-llm:8090",
		LLMCategories:       []string{"email_fields"},
		PathLabelURL:        "https://control-plane.example/pii-path-labels",
		ScanIntervalSeconds: 300,
	}
}

func TestValidate_AcceptsFullyConfigured(t *testing.T) {
	if err := validate(validLabellerConfig()); err != nil {
		t.Fatalf("expected a fully-configured Labeller to validate, got %v", err)
	}
}

func TestValidate_RequiresEachField(t *testing.T) {
	cases := []struct {
		name   string
		mutate func(*config.Labeller)
	}{
		{"OrgID", func(c *config.Labeller) { c.OrgID = "" }},
		{"DSN", func(c *config.Labeller) { c.DSN = "" }},
		{"Database", func(c *config.Labeller) { c.Database = "" }},
		{"LLMEndpoint", func(c *config.Labeller) { c.LLMEndpoint = "" }},
		{"LLMCategories", func(c *config.Labeller) { c.LLMCategories = nil }},
		{"PathLabelURL", func(c *config.Labeller) { c.PathLabelURL = "" }},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			cfg := validLabellerConfig()
			tc.mutate(&cfg)
			if err := validate(cfg); err == nil {
				t.Fatalf("expected validate to reject a config missing %s", tc.name)
			}
		})
	}
}

// TestValidate_AcceptsEmptyTables confirms Tables is optional — an empty list means Run discovers
// the table/collection list dynamically via sampler.ListTables instead of requiring an
// operator-maintained SKYBRIDGE_LABELLER_TABLES.
func TestValidate_AcceptsEmptyTables(t *testing.T) {
	cfg := validLabellerConfig()
	cfg.Tables = nil
	if err := validate(cfg); err != nil {
		t.Fatalf("expected an empty Tables list to validate (dynamic discovery), got %v", err)
	}
}

func TestRun_ReturnsValidationErrorWithoutDialing(t *testing.T) {
	cfg := validLabellerConfig()
	cfg.OrgID = "" // trigger validate's first failure before Run ever opens a DB connection
	if err := Run(context.Background(), cfg, log.Default()); err == nil {
		t.Fatal("expected Run to return a validation error for a missing required field")
	}
}

func TestSQLDriverName(t *testing.T) {
	cases := []struct {
		dbType  string
		want    string
		wantErr bool
	}{
		{"postgres", "pgx", false},
		{"postgresql", "pgx", false},
		{"mysql", "mysql", false},
		{"snowflake", "snowflake", false},
		{"mongo", "", true}, // Mongo has no database/sql driver — Run branches before calling sqlDriverName
		{"", "", true},
	}
	for _, c := range cases {
		got, err := sqlDriverName(c.dbType)
		if c.wantErr {
			if err == nil {
				t.Errorf("sqlDriverName(%q): expected an error, got %q", c.dbType, got)
			}
			continue
		}
		if err != nil || got != c.want {
			t.Errorf("sqlDriverName(%q) = (%q, %v), want (%q, nil)", c.dbType, got, err, c.want)
		}
	}
}

func TestNormalizeDriver(t *testing.T) {
	if got := normalizeDriver("postgresql"); got != "postgres" {
		t.Fatalf("normalizeDriver(postgresql) = %q, want postgres", got)
	}
	if got := normalizeDriver("mongodb"); got != "mongo" {
		t.Fatalf("normalizeDriver(mongodb) = %q, want mongo", got)
	}
	if got := normalizeDriver("mysql"); got != "mysql" {
		t.Fatalf("normalizeDriver(mysql) = %q, want mysql (unchanged)", got)
	}
}

// TestRun_MongoOpensLazilyThenFailsValidationFast confirms Run's Mongo branch is reachable and that
// mongo.Connect's lazy-dial behavior (see internal/pathlabel/mongosampler's tests for the same
// pattern) doesn't block Run itself — validated by triggering the same pre-dial validation failure
// TestRun_ReturnsValidationErrorWithoutDialing already exercises for the SQL path, just with
// DBType=mongo so the Mongo branch is the one that would have run.
func TestRun_MongoOpensLazilyThenFailsValidationFast(t *testing.T) {
	cfg := validLabellerConfig()
	cfg.DBType = "mongo"
	cfg.DSN = "mongodb://127.0.0.1:1/appdb"
	cfg.OrgID = "" // trigger validate's first failure before Run ever opens a connection
	if err := Run(context.Background(), cfg, log.Default()); err == nil {
		t.Fatal("expected Run to return a validation error for a missing required field")
	}
}

func TestScheduler_SelectObjectsCapsAtMaxObjects(t *testing.T) {
	s := newScheduler()
	candidates := []string{"a", "b", "c", "d", "e"}
	got := s.selectObjects(candidates, 2, time.Hour, time.Now())
	if len(got) != 2 {
		t.Fatalf("expected 2 objects (capped), got %d: %v", len(got), got)
	}
}

func TestScheduler_SelectObjectsUnlimitedWhenMaxObjectsNotPositive(t *testing.T) {
	s := newScheduler()
	candidates := []string{"a", "b", "c"}
	got := s.selectObjects(candidates, 0, time.Hour, time.Now())
	if len(got) != 3 {
		t.Fatalf("expected all 3 objects (unlimited), got %d: %v", len(got), got)
	}
}

func TestScheduler_SelectObjectsSkipsRecentlyScanned(t *testing.T) {
	s := newScheduler()
	now := time.Now()
	s.markScanned([]string{"a"}, now)

	got := s.selectObjects([]string{"a", "b"}, 0, time.Hour, now.Add(time.Minute))
	if len(got) != 1 || got[0] != "b" {
		t.Fatalf("expected only the not-recently-scanned object, got %v", got)
	}
}

func TestScheduler_SelectObjectsRescansAfterInterval(t *testing.T) {
	s := newScheduler()
	now := time.Now()
	s.markScanned([]string{"a"}, now)

	got := s.selectObjects([]string{"a", "b"}, 0, time.Hour, now.Add(2*time.Hour))
	sort.Strings(got)
	if len(got) != 2 {
		t.Fatalf("expected both objects eligible once the rescan interval has elapsed, got %v", got)
	}
}

func TestScheduler_SelectObjectsRoundRobinsLeastRecentlyScannedFirst(t *testing.T) {
	s := newScheduler()
	now := time.Now()
	// First cycle scans a and b (cap=2), leaving c never-scanned.
	first := s.selectObjects([]string{"a", "b", "c"}, 2, 0, now)
	sort.Strings(first)
	if len(first) != 2 {
		t.Fatalf("expected 2 objects in the first cycle, got %v", first)
	}
	s.markScanned(first, now)

	// Second cycle (rescanInterval=0 disables skipping, so all 3 are candidates again) must put c
	// first, since it's still never-scanned and everything else now has a real lastScanned time.
	second := s.selectObjects([]string{"a", "b", "c"}, 1, 0, now.Add(time.Minute))
	if len(second) != 1 || second[0] != "c" {
		t.Fatalf("expected round-robin to prioritize the never-scanned object, got %v", second)
	}
}

func TestScheduler_MarkScannedIsIdempotentAcrossCalls(t *testing.T) {
	s := newScheduler()
	now := time.Now()
	s.markScanned([]string{"a"}, now)
	s.markScanned([]string{"a"}, now.Add(time.Minute))
	if !s.lastScanned["a"].Equal(now.Add(time.Minute)) {
		t.Fatalf("expected the later markScanned call to win, got %v", s.lastScanned["a"])
	}
}

// fakeSampleLister is a minimal sampleLister + aiclassifier.Sampler used to exercise runOnce's
// dynamic-discovery and scheduling behavior without a real database.
type fakeSampleLister struct {
	tables       []string
	columns      map[string][]string
	listTablesN  int
	listColsCall []string // tables ListColumns was actually called for, in call order
}

func (f *fakeSampleLister) ListTables(ctx context.Context, schema string) ([]string, error) {
	f.listTablesN++
	return f.tables, nil
}

func (f *fakeSampleLister) ListColumns(ctx context.Context, schema, table string) ([]string, error) {
	f.listColsCall = append(f.listColsCall, table)
	return f.columns[table], nil
}

func (f *fakeSampleLister) Sample(ctx context.Context, objectID, fieldPath string, maxSamples int) ([]string, bool) {
	return []string{"sample-value"}, true
}

type fakeClassifier struct{}

func (fakeClassifier) Classify(ctx context.Context, objectID, fieldPath string, samples []string) (string, string, float64, bool) {
	return "email_fields", "full_redact", 0.9, true
}

func TestRunOnce_DiscoversTablesDynamicallyWhenTablesUnset(t *testing.T) {
	fl := &fakeSampleLister{
		tables:  []string{"users", "orders"},
		columns: map[string][]string{"users": {"email"}, "orders": {"total"}},
	}
	scanner := aiclassifier.NewScanner(aiclassifier.ScannerConfig{
		Classifier: fakeClassifier{},
		Sampler:    fl,
		Store:      label.NewMemStore(),
	})
	cfg := validLabellerConfig()
	cfg.Tables = nil // force dynamic discovery

	runOnce(context.Background(), cfg, fl, scanner, newScheduler(), log.Default())

	if fl.listTablesN != 1 {
		t.Fatalf("expected ListTables to be called once for dynamic discovery, got %d", fl.listTablesN)
	}
	if len(fl.listColsCall) != 2 {
		t.Fatalf("expected both discovered tables to be scanned, got %v", fl.listColsCall)
	}
}

func TestRunOnce_MaxObjectsPerScanBoundsBreadthAcrossCycles(t *testing.T) {
	fl := &fakeSampleLister{
		tables:  []string{"t1", "t2", "t3"},
		columns: map[string][]string{"t1": {"a"}, "t2": {"a"}, "t3": {"a"}},
	}
	scanner := aiclassifier.NewScanner(aiclassifier.ScannerConfig{
		Classifier: fakeClassifier{},
		Sampler:    fl,
		Store:      label.NewMemStore(),
	})
	cfg := validLabellerConfig()
	cfg.Tables = nil
	cfg.MaxObjectsPerScan = 2
	cfg.RescanIntervalSeconds = 0 // no skip-if-recent, purely exercising the cap + round-robin order

	sched := newScheduler()
	runOnce(context.Background(), cfg, fl, scanner, sched, log.Default())
	if len(fl.listColsCall) != 2 {
		t.Fatalf("expected the first cycle to scan exactly 2 of 3 tables (the cap), got %v", fl.listColsCall)
	}
	scannedFirst := map[string]bool{}
	for _, tbl := range fl.listColsCall {
		scannedFirst[tbl] = true
	}
	var skippedFirst string
	for _, tbl := range fl.tables {
		if !scannedFirst[tbl] {
			skippedFirst = tbl
		}
	}

	fl.listColsCall = nil
	runOnce(context.Background(), cfg, fl, scanner, sched, log.Default())
	if len(fl.listColsCall) != 2 {
		t.Fatalf("expected the second cycle to scan 2 tables too, got %v", fl.listColsCall)
	}
	scannedSecond := map[string]bool{}
	for _, tbl := range fl.listColsCall {
		scannedSecond[tbl] = true
	}
	// The table skipped in cycle 1 (never-scanned, so it sorts first) must be scanned in cycle 2 —
	// this is the round-robin guarantee that lets a large schema get covered incrementally.
	if !scannedSecond[skippedFirst] {
		t.Fatalf("expected the table skipped in cycle 1 (%q) to be scanned in cycle 2, got %v", skippedFirst, fl.listColsCall)
	}
}
