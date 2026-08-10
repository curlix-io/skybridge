//go:build querystudio

package dbexec

import (
	"context"
	"testing"

	"github.com/curlix-io/skybridge/internal/edge"
	"github.com/curlix-io/skybridge/internal/edge/dbquery"
)

func TestRegisterMigrationRegistersTool(t *testing.T) {
	reg := edge.NewRegistry()
	RegisterMigration(reg, MigrationOptions{})
	if !reg.Has(ToolDBExecMigration) {
		t.Fatal("expected db_exec_migration to be registered")
	}
}

func TestMigrationRunMissingArgs(t *testing.T) {
	reg := edge.NewRegistry()
	RegisterMigration(reg, MigrationOptions{})
	res := reg.Dispatch(context.Background(), edge.ToolCall{
		Name:      ToolDBExecMigration,
		Arguments: map[string]any{"database": "app"},
	})
	if res["ok"] != false {
		t.Fatalf("expected ok=false: %+v", res)
	}
}

func TestMigrationRunMissingTarget(t *testing.T) {
	reg := edge.NewRegistry()
	RegisterMigration(reg, MigrationOptions{Targets: []dbquery.Target{}})
	res := reg.Dispatch(context.Background(), edge.ToolCall{
		Name: ToolDBExecMigration,
		Arguments: map[string]any{
			"database":   "app",
			"db_type":    "postgres",
			"statements": []any{"CREATE TABLE t (x int)"},
		},
	})
	if res["ok"] != false || res["tool"] != ToolDBExecMigration {
		t.Fatalf("expected ok=false tool=%s: %+v", ToolDBExecMigration, res)
	}
}

// TestMigrationRunDialFailureSurfacesAppliedStatements exercises the SQL (non-mongo) branch of
// run(), all the way to dbquery.ExecuteMigration's dial failure, and confirms
// migrationResultToEdgeResult's failure shape (applied_statements + error, ok=false).
func TestMigrationRunDialFailureSurfacesAppliedStatements(t *testing.T) {
	reg := edge.NewRegistry()
	RegisterMigration(reg, MigrationOptions{
		Targets: []dbquery.Target{{DBType: "postgres", DatabaseName: "app", Host: "127.0.0.1:1"}},
	})
	res := reg.Dispatch(context.Background(), edge.ToolCall{
		Name: ToolDBExecMigration,
		Arguments: map[string]any{
			"database":   "app",
			"db_type":    "postgres",
			"statements": []any{"CREATE TABLE t (x int)"},
		},
	})
	if res["ok"] != false || res["tool"] != ToolDBExecMigration {
		t.Fatalf("expected ok=false tool=%s: %+v", ToolDBExecMigration, res)
	}
	if _, ok := res["applied_statements"]; !ok {
		t.Fatalf("expected applied_statements key present on failure, got %+v", res)
	}
	if _, ok := res["error"]; !ok {
		t.Fatalf("expected error key present, got %+v", res)
	}
}

// TestMigrationRunRoutesMongoToMongoshPath confirms run() routes db_type "mongo"/"mongodb" to the
// runMongoMigration path (mongo_migration.go) rather than dbquery.ExecuteMigration — with no mongosh
// binary available in the test environment, the distinguishing error is
// "mongosh binary not found", not a SQL dial error.
func TestMigrationRunRoutesMongoToMongoshPath(t *testing.T) {
	reg := edge.NewRegistry()
	RegisterMigration(reg, MigrationOptions{
		Targets:    []dbquery.Target{{DBType: "mongo", DatabaseName: "app", Host: "127.0.0.1:1"}},
		MongoshBin: "", // force findMongoshPath(), which should find nothing on a bare test runner
	})
	res := reg.Dispatch(context.Background(), edge.ToolCall{
		Name: ToolDBExecMigration,
		Arguments: map[string]any{
			"database":   "app",
			"db_type":    "mongodb",
			"statements": []any{"db.x.insertOne({})"},
		},
	})
	if res["ok"] != false || res["tool"] != ToolDBExecMigration {
		t.Fatalf("expected ok=false tool=%s: %+v", ToolDBExecMigration, res)
	}
}

func TestMigrationResultToEdgeResultSuccess(t *testing.T) {
	res, err := migrationResultToEdgeResult(MigrationResult{AppliedStatements: 3}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if res["ok"] != true || res["applied_statements"] != 3 || res["tool"] != ToolDBExecMigration {
		t.Fatalf("unexpected success result: %+v", res)
	}
	if _, ok := res["error"]; ok {
		t.Fatalf("expected no error key on success, got %+v", res)
	}
}

// TestStringListArg covers every input shape stringListArg accepts: []string, []any (mixed,
// trimming blanks), a bare string, absent/nil, and an unsupported type.
func TestStringListArg(t *testing.T) {
	if got := stringListArg(map[string]any{"x": []string{"a", "b"}}, "x"); len(got) != 2 {
		t.Fatalf("expected 2 items from []string, got %v", got)
	}
	if got := stringListArg(map[string]any{"x": []any{"a", "  b  ", "", 3}}, "x"); len(got) != 3 || got[2] != "3" {
		t.Fatalf("expected blanks skipped and non-strings stringified, got %v", got)
	}
	if got := stringListArg(map[string]any{"x": "solo"}, "x"); len(got) != 1 || got[0] != "solo" {
		t.Fatalf("expected single-element list from bare string, got %v", got)
	}
	if got := stringListArg(map[string]any{"x": "   "}, "x"); got != nil {
		t.Fatalf("expected nil for a blank bare string, got %v", got)
	}
	if got := stringListArg(map[string]any{}, "x"); got != nil {
		t.Fatalf("expected nil for absent key, got %v", got)
	}
	if got := stringListArg(map[string]any{"x": nil}, "x"); got != nil {
		t.Fatalf("expected nil for nil value, got %v", got)
	}
	if got := stringListArg(map[string]any{"x": 42}, "x"); got != nil {
		t.Fatalf("expected nil for an unsupported type, got %v", got)
	}
}
