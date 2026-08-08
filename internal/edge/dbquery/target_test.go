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
