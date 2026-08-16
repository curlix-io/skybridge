package dbquery

import (
	"testing"

	"github.com/curlix-io/skybridge/internal/tunnel"
)

func TestParseTargetsNormalizesDBType(t *testing.T) {
	ts := ParseTargets(`[{"db_type":"POSTGRESQL","host":"a"},{"db_type":"MongoDB","host":"b"}]`)
	if len(ts) != 2 {
		t.Fatalf("expected 2 targets, got %d", len(ts))
	}
	if ts[0].DBType != "postgres" {
		t.Fatalf("expected postgresql normalized to postgres, got %q", ts[0].DBType)
	}
	if ts[1].DBType != "mongo" {
		t.Fatalf("expected mongodb normalized to mongo, got %q", ts[1].DBType)
	}
}

func TestParseTargetsEmptyAndInvalid(t *testing.T) {
	if got := ParseTargets(""); got != nil {
		t.Fatalf("expected nil for empty input, got %v", got)
	}
	if got := ParseTargets("not json"); got != nil {
		t.Fatalf("expected nil for invalid JSON, got %v", got)
	}
}

func TestNormalizeDBType(t *testing.T) {
	cases := map[string]string{
		"postgresql": "postgres",
		"POSTGRESQL": "postgres",
		"mongodb":    "mongo",
		" MySQL ":    "mysql",
		"":           "",
	}
	for in, want := range cases {
		if got := normalizeDBType(in); got != want {
			t.Errorf("normalizeDBType(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestMergeWireTargetsAppendsNormalizedWireEntries(t *testing.T) {
	studio := []Target{{DBType: "postgres", DatabaseName: "app", Host: "a:5432"}}
	wire := []tunnel.Target{{Name: "prod-mysql", DBType: "MYSQL", Addr: "b:3306"}}
	merged := MergeWireTargets(studio, wire)
	if len(merged) != 2 {
		t.Fatalf("expected 2 targets, got %d", len(merged))
	}
	if merged[1].DBType != "mysql" || merged[1].Host != "b:3306" || merged[1].Name != "prod-mysql" {
		t.Fatalf("unexpected merged wire target: %+v", merged[1])
	}
}

func TestMergeWireTargetsDoesNotMutateInputSlice(t *testing.T) {
	studio := []Target{{DBType: "postgres"}}
	_ = MergeWireTargets(studio, []tunnel.Target{{DBType: "mysql"}})
	if len(studio) != 1 {
		t.Fatalf("expected input studio slice untouched, got len %d", len(studio))
	}
}

func TestTargetMatches(t *testing.T) {
	targets := []Target{
		{DBType: "postgres", AWSAccountID: "111", DatabaseName: "app", Host: "db:5432"},
		{DBType: "mysql", AWSAccountID: "222", DatabaseName: "shop", Host: "mysql:3306"},
		{DBType: "postgres", Name: "reporting", Host: "rep:5432"},
	}
	if _, ok := Resolve(targets, "postgres", "111", "app"); !ok {
		t.Fatal("expected postgres/111/app match")
	}
	if _, ok := Resolve(targets, "postgres", "999", "app"); ok {
		t.Fatal("wrong account should not match")
	}
	if _, ok := Resolve(targets, "postgres", "111", "other"); ok {
		t.Fatal("wrong database should not match")
	}
	if _, ok := Resolve(targets, "mongo", "111", "app"); ok {
		t.Fatal("wrong db_type should not match")
	}
	// Name-based match only applies when DatabaseName is empty.
	if got, ok := Resolve(targets, "postgres", "", "reporting"); !ok || got.Name != "reporting" {
		t.Fatalf("expected name-based match for target with empty DatabaseName, got %+v ok=%v", got, ok)
	}
	if _, ok := Resolve(nil, "postgres", "111", "app"); ok {
		t.Fatal("expected no match against nil target list")
	}
}

func TestTargetFromOverrideHostAndPort(t *testing.T) {
	got, ok := TargetFromOverride("postgres", "app", map[string]any{
		"host": "db.internal",
		"port": float64(5432), // json.Unmarshal decodes numbers to float64
		"credential": map[string]any{
			"user":   "u",
			"secret": "p",
		},
	})
	if !ok {
		t.Fatal("expected ok=true")
	}
	if got.Host != "db.internal:5432" {
		t.Fatalf("expected combined host:port, got %q", got.Host)
	}
	if got.User != "u" || got.Password != "p" {
		t.Fatalf("expected credential to populate User/Password, got %+v", got)
	}
	if got.DatabaseName != "app" {
		t.Fatalf("expected DatabaseName to carry through, got %q", got.DatabaseName)
	}
}

func TestTargetFromOverrideHostWithoutPort(t *testing.T) {
	got, ok := TargetFromOverride("mysql", "shop", map[string]any{"host": "mysql.internal"})
	if !ok {
		t.Fatal("expected ok=true")
	}
	if got.Host != "mysql.internal" {
		t.Fatalf("expected bare host with no port suffix, got %q", got.Host)
	}
}

func TestTargetFromOverrideDSNOnly(t *testing.T) {
	got, ok := TargetFromOverride("mongo", "app", map[string]any{
		"dsn": "mongodb+srv://u:p@cluster0.example.mongodb.net/app?replicaSet=rs0",
	})
	if !ok {
		t.Fatal("expected ok=true for dsn-only override (no host)")
	}
	if got.DSN == "" || got.Host != "" {
		t.Fatalf("expected DSN set and Host empty, got DSN=%q Host=%q", got.DSN, got.Host)
	}
}

func TestTargetFromOverrideRejectsInvalid(t *testing.T) {
	if _, ok := TargetFromOverride("postgres", "app", nil); ok {
		t.Fatal("expected ok=false for nil override")
	}
	if _, ok := TargetFromOverride("postgres", "app", map[string]any{}); ok {
		t.Fatal("expected ok=false for empty override (no host, no dsn)")
	}
	if _, ok := TargetFromOverride("postgres", "app", map[string]any{"port": float64(5432)}); ok {
		t.Fatal("expected ok=false when port is present but host/dsn are not")
	}
}

func TestOverridePortCoercion(t *testing.T) {
	cases := []struct {
		name string
		in   any
		want string
	}{
		{"float64", float64(5432), "5432"},
		{"zero float64 is absent", float64(0), ""},
		{"negative float64 is absent", float64(-1), ""},
		{"int", 3306, "3306"},
		{"string", "27017", "27017"},
		{"nil", nil, ""},
		{"unsupported type", true, ""},
	}
	for _, c := range cases {
		if got := overridePort(c.in); got != c.want {
			t.Errorf("%s: overridePort(%v) = %q, want %q", c.name, c.in, got, c.want)
		}
	}
}
