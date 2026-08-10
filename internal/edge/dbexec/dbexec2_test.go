//go:build querystudio

package dbexec

import (
	"context"
	"testing"

	"github.com/curlix-io/skybridge/internal/edge"
	"github.com/curlix-io/skybridge/internal/edge/dbquery"
)

// TestRunMySQLMissingArgs / TestRunMongoMissingArgs exercise the runMySQL/runMongo thin wrappers
// (currently 0% covered) via the registry, mirroring TestDbExecMissingArgs's postgres case.
func TestRunMySQLMissingArgs(t *testing.T) {
	reg := edge.NewRegistry()
	Register(reg, Options{})
	res := reg.Dispatch(context.Background(), edge.ToolCall{
		Name:      ToolDBQueryMySQL,
		Arguments: map[string]any{"database": "app"},
	})
	if res["ok"] != false {
		t.Fatalf("expected ok=false: %+v", res)
	}
}

func TestRunMongoMissingArgs(t *testing.T) {
	reg := edge.NewRegistry()
	Register(reg, Options{})
	res := reg.Dispatch(context.Background(), edge.ToolCall{
		Name:      ToolDBQueryMongo,
		Arguments: map[string]any{"database": "app"},
	})
	if res["ok"] != false {
		t.Fatalf("expected ok=false: %+v", res)
	}
}

// TestRunMySQLMissingTarget / TestRunMongoMissingTarget exercise the "no local target" branch of
// run() through the mysql/mongo wrappers specifically (toolName's "mongo" special case, too).
func TestRunMySQLMissingTarget(t *testing.T) {
	reg := edge.NewRegistry()
	Register(reg, Options{Targets: []dbquery.Target{}})
	res := reg.Dispatch(context.Background(), edge.ToolCall{
		Name: ToolDBQueryMySQL,
		Arguments: map[string]any{
			"database":  "app",
			"statement": "SELECT 1",
		},
	})
	if res["ok"] != false || res["tool"] != ToolDBQueryMySQL {
		t.Fatalf("expected ok=false tool=%s: %+v", ToolDBQueryMySQL, res)
	}
}

func TestRunMongoMissingTarget(t *testing.T) {
	reg := edge.NewRegistry()
	Register(reg, Options{Targets: []dbquery.Target{}})
	res := reg.Dispatch(context.Background(), edge.ToolCall{
		Name: ToolDBQueryMongo,
		Arguments: map[string]any{
			"database":  "app",
			"statement": "db.users.find({})",
		},
	})
	if res["ok"] != false || res["tool"] != ToolDBQueryMongo {
		t.Fatalf("expected ok=false tool=%s: %+v", ToolDBQueryMongo, res)
	}
}

// TestRunWriteMissingArgs / TestRunWriteMissingTarget exercise runWrite (0% covered), which is
// distinct from run() — no read_only knob, no PII masking, EnforceReadOnly always false.
func TestRunWriteMissingArgs(t *testing.T) {
	reg := edge.NewRegistry()
	Register(reg, Options{})
	res := reg.Dispatch(context.Background(), edge.ToolCall{
		Name:      ToolDBExecuteWrite,
		Arguments: map[string]any{"database": "app"},
	})
	if res["ok"] != false {
		t.Fatalf("expected ok=false: %+v", res)
	}
}

func TestRunWriteMissingTarget(t *testing.T) {
	reg := edge.NewRegistry()
	Register(reg, Options{Targets: []dbquery.Target{}})
	res := reg.Dispatch(context.Background(), edge.ToolCall{
		Name: ToolDBExecuteWrite,
		Arguments: map[string]any{
			"db_type":   "postgres",
			"database":  "app",
			"statement": "DELETE FROM t",
		},
	})
	if res["ok"] != false || res["tool"] != ToolDBExecuteWrite {
		t.Fatalf("expected ok=false tool=%s: %+v", ToolDBExecuteWrite, res)
	}
}

// TestRunWriteDialFailureSurfacesAsErrorResult exercises runWrite's dbquery.Execute error branch
// (as opposed to the "no local target" branch above) by resolving a real target that then fails to
// dial — proving runWrite's EnforceReadOnly is never set (dbquery.Execute would reject
// EnforceReadOnly+Write together, which is not the error we expect here; any error must be a dial
// error, not "mutually exclusive").
func TestRunWriteDialFailureSurfacesAsErrorResult(t *testing.T) {
	reg := edge.NewRegistry()
	Register(reg, Options{
		Targets: []dbquery.Target{{DBType: "postgres", DatabaseName: "app", Host: "127.0.0.1:1"}},
	})
	res := reg.Dispatch(context.Background(), edge.ToolCall{
		Name: ToolDBExecuteWrite,
		Arguments: map[string]any{
			"db_type":   "postgres",
			"database":  "app",
			"statement": "DELETE FROM t",
		},
	})
	if res["ok"] != false {
		t.Fatalf("expected ok=false, got %+v", res)
	}
	msg, _ := res["error"].(string)
	if msg == "" {
		t.Fatal("expected a non-empty error message")
	}
	if msg == "dbquery: EnforceReadOnly and Write are mutually exclusive" {
		t.Fatalf("runWrite must never set EnforceReadOnly; got the mutual-exclusivity error: %s", msg)
	}
}

// TestRunReadOnlyDialFailureSurfacesAsErrorResult is the read-only counterpart: run() (used by
// runPostgres/runMySQL/runMongo) resolves a target then fails to dial/execute, exercising the
// dbquery.Execute error branch inside run() (as opposed to the "no local target" branch already
// covered by TestDbExecMissingTarget).
func TestRunReadOnlyDialFailureSurfacesAsErrorResult(t *testing.T) {
	reg := edge.NewRegistry()
	Register(reg, Options{
		Targets: []dbquery.Target{{DBType: "postgres", DatabaseName: "app", Host: "127.0.0.1:1"}},
	})
	res := reg.Dispatch(context.Background(), edge.ToolCall{
		Name: ToolDBQueryPostgres,
		Arguments: map[string]any{
			"database":  "app",
			"statement": "SELECT 1",
		},
	})
	if res["ok"] != false || res["tool"] != ToolDBQueryPostgres {
		t.Fatalf("expected ok=false tool=%s: %+v", ToolDBQueryPostgres, res)
	}
}

// TestToolNameMapsEveryDBType exercises toolName's mongo special-case and its default branch for
// every other db_type.
func TestToolNameMapsEveryDBType(t *testing.T) {
	cases := map[string]string{
		"postgres": ToolDBQueryPostgres,
		"mysql":    ToolDBQueryMySQL,
		"mongo":    ToolDBQueryMongo,
		"oracle":   "db_query_oracle",
	}
	for dbType, want := range cases {
		if got := toolName(dbType); got != want {
			t.Errorf("toolName(%q) = %q, want %q", dbType, got, want)
		}
	}
}

// TestExtractRows covers extractRows' three shapes: []map[string]any, []any of maps, and absent/
// malformed results (which must return nil, never panic).
func TestExtractRows(t *testing.T) {
	if got := extractRows(map[string]any{
		"results": map[string]any{"data": []map[string]any{{"a": 1}}},
	}); len(got) != 1 {
		t.Fatalf("expected 1 row from []map[string]any shape, got %d", len(got))
	}
	if got := extractRows(map[string]any{
		"results": map[string]any{"data": []any{map[string]any{"a": 1}, "not a map"}},
	}); len(got) != 1 {
		t.Fatalf("expected 1 row from []any shape (non-map entries skipped), got %d", len(got))
	}
	if got := extractRows(map[string]any{}); got != nil {
		t.Fatalf("expected nil when results is absent, got %v", got)
	}
	if got := extractRows(map[string]any{"results": "not a map"}); got != nil {
		t.Fatalf("expected nil when results is malformed, got %v", got)
	}
	if got := extractRows(map[string]any{"results": map[string]any{"data": "not a list"}}); got != nil {
		t.Fatalf("expected nil when data is malformed, got %v", got)
	}
}

// TestBoolArg / TestIntArg cover every branch (absent key, nil, bool, string variants, invalid
// string, wrong type) of the two coercion helpers.
func TestBoolArg(t *testing.T) {
	cases := []struct {
		name string
		args map[string]any
		def  bool
		want bool
	}{
		{"absent key uses default", map[string]any{}, true, true},
		{"nil value uses default", map[string]any{"x": nil}, false, false},
		{"bool true", map[string]any{"x": true}, false, true},
		{"bool false", map[string]any{"x": false}, true, false},
		{"string true variants", map[string]any{"x": "YES"}, false, true},
		{"string false variants", map[string]any{"x": "off"}, true, false},
		{"unrecognized string uses default", map[string]any{"x": "maybe"}, true, true},
		{"non-bool non-string type uses default", map[string]any{"x": 42}, false, false},
	}
	for _, c := range cases {
		if got := boolArg(c.args, "x", c.def); got != c.want {
			t.Errorf("%s: boolArg() = %v, want %v", c.name, got, c.want)
		}
	}
}

func TestIntArg(t *testing.T) {
	cases := []struct {
		name string
		args map[string]any
		def  int
		want int
	}{
		{"absent key uses default", map[string]any{}, 7, 7},
		{"nil value uses default", map[string]any{"x": nil}, 7, 7},
		{"int", map[string]any{"x": 5}, 0, 5},
		{"int64", map[string]any{"x": int64(9)}, 0, 9},
		{"float64", map[string]any{"x": float64(3)}, 0, 3},
		{"valid numeric string", map[string]any{"x": "42"}, 0, 42},
		{"invalid string uses default", map[string]any{"x": "not a number"}, 11, 11},
		{"zero numeric string uses default", map[string]any{"x": "0"}, 11, 11},
		{"unsupported type uses default", map[string]any{"x": true}, 3, 3},
	}
	for _, c := range cases {
		if got := intArg(c.args, "x", c.def); got != c.want {
			t.Errorf("%s: intArg() = %d, want %d", c.name, got, c.want)
		}
	}
}

// TestStrArg covers strArg's absent/nil/trim behavior, not exercised elsewhere in isolation.
func TestStrArg(t *testing.T) {
	if got := strArg(map[string]any{}, "x"); got != "" {
		t.Fatalf("expected empty string for absent key, got %q", got)
	}
	if got := strArg(map[string]any{"x": nil}, "x"); got != "" {
		t.Fatalf("expected empty string for nil value, got %q", got)
	}
	if got := strArg(map[string]any{"x": "  hello  "}, "x"); got != "hello" {
		t.Fatalf("expected trimmed value, got %q", got)
	}
	if got := strArg(map[string]any{"x": 42}, "x"); got != "42" {
		t.Fatalf("expected fmt.Sprint fallback for non-string, got %q", got)
	}
}
