package labeller

import (
	"context"
	"log"
	"testing"

	"github.com/curlix-io/skybridge/internal/config"
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
		{"Tables", func(c *config.Labeller) { c.Tables = nil }},
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
		{"snowflake", "", true},
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
	if got := normalizeDriver("mysql"); got != "mysql" {
		t.Fatalf("normalizeDriver(mysql) = %q, want mysql (unchanged)", got)
	}
}
