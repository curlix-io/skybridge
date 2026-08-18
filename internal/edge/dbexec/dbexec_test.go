package dbexec

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/curlix-io/skybridge/internal/edge"
	"github.com/curlix-io/skybridge/internal/edge/dbquery"
)

func TestDbExecMissingTarget(t *testing.T) {
	reg := edge.NewRegistry()
	Register(reg, Options{Targets: []dbquery.Target{}})
	res := reg.Dispatch(context.Background(), edge.ToolCall{
		Name: ToolDBQueryPostgres,
		Arguments: map[string]any{
			"database":         "app",
			"connection_scope": "111",
			"statement":        "SELECT 1",
			"read_only":        true,
		},
	})
	if res["ok"] != false {
		t.Fatalf("expected ok=false: %+v", res)
	}
}

func TestDbExecMissingArgs(t *testing.T) {
	reg := edge.NewRegistry()
	Register(reg, Options{})
	res := reg.Dispatch(context.Background(), edge.ToolCall{
		Name: ToolDBQueryPostgres,
		Arguments: map[string]any{
			"database": "app",
		},
	})
	if res["ok"] != false {
		t.Fatalf("expected ok=false: %+v", res)
	}
}

func TestRegistryHasDbQueryTools(t *testing.T) {
	reg := edge.NewRegistry()
	Register(reg, Options{})
	for _, name := range []string{ToolDBQueryPostgres, ToolDBQueryMySQL, ToolDBQueryMongo, ToolDBQuerySnowflake, ToolDBQueryNeo4j} {
		if !reg.Has(name) {
			t.Fatalf("missing %s", name)
		}
	}
}

func TestDbExecNeo4jMissingTargetNoFallback(t *testing.T) {
	reg := edge.NewRegistry()
	Register(reg, Options{Targets: []dbquery.Target{}})
	res := reg.Dispatch(context.Background(), edge.ToolCall{
		Name: ToolDBQueryNeo4j,
		Arguments: map[string]any{
			"database":         "neo4j",
			"connection_scope": "111",
			"statement":        "MATCH (n) RETURN n LIMIT 1",
			"read_only":        true,
		},
	})
	if res["ok"] != false {
		t.Fatalf("expected ok=false: %+v", res)
	}
	if res["tool"] != ToolDBQueryNeo4j {
		t.Fatalf("expected tool=%s: %+v", ToolDBQueryNeo4j, res)
	}
}

func TestDbExecNeo4jMissingArgs(t *testing.T) {
	reg := edge.NewRegistry()
	Register(reg, Options{})
	res := reg.Dispatch(context.Background(), edge.ToolCall{
		Name:      ToolDBQueryNeo4j,
		Arguments: map[string]any{"database": "neo4j"},
	})
	if res["ok"] != false {
		t.Fatalf("expected ok=false: %+v", res)
	}
}

// TestDbExecNeo4jStaticURIFallback exercises resolveNeo4jStaticTarget's env-var fallback path:
// with no dynamic "connection" override and no matching static Targets entry, a non-empty
// Neo4jStaticURI must still resolve a target (so run() reaches dbquery.Execute/executeNeo4j
// instead of short-circuiting on "no local target") — the dial itself then fails against an
// unreachable address, which is still a materially different, later failure mode than
// "no local target for neo4j/.../...".
func TestDbExecNeo4jStaticURIFallback(t *testing.T) {
	reg := edge.NewRegistry()
	Register(reg, Options{
		Targets:        []dbquery.Target{},
		Neo4jStaticURI: "bolt://127.0.0.1:1", // unreachable on purpose; only target resolution is under test
		QueryTimeout:   200 * time.Millisecond,
	})
	res := reg.Dispatch(context.Background(), edge.ToolCall{
		Name: ToolDBQueryNeo4j,
		Arguments: map[string]any{
			"database":  "neo4j",
			"statement": "MATCH (n) RETURN n LIMIT 1",
			"read_only": true,
		},
	})
	if res["ok"] != false {
		t.Fatalf("expected ok=false (connect failure, not target-resolution failure): %+v", res)
	}
	if msg, _ := res["error"].(string); strings.Contains(msg, "no local target") {
		t.Fatalf("expected a connection error, not a target-resolution error: %+v", res)
	}
}

// TestResolveNeo4jStaticTarget covers resolveNeo4jStaticTarget directly: empty URI never resolves
// (the "neither dynamic override nor static config" case, which must surface a clear "no local
// target" error rather than silently trying to dial an empty address), non-empty URI always does.
func TestResolveNeo4jStaticTarget(t *testing.T) {
	if _, ok := resolveNeo4jStaticTarget("", "neo4j"); ok {
		t.Fatalf("expected empty static URI to not resolve")
	}
	target, ok := resolveNeo4jStaticTarget("bolt://localhost:7687", "neo4j")
	if !ok {
		t.Fatalf("expected non-empty static URI to resolve")
	}
	if target.DSN != "bolt://localhost:7687" || target.DatabaseName != "neo4j" {
		t.Fatalf("unexpected target: %+v", target)
	}
}

func TestDbExecSnowflakeMissingTarget(t *testing.T) {
	reg := edge.NewRegistry()
	Register(reg, Options{Targets: []dbquery.Target{}})
	res := reg.Dispatch(context.Background(), edge.ToolCall{
		Name: ToolDBQuerySnowflake,
		Arguments: map[string]any{
			"database":         "app",
			"connection_scope": "111",
			"statement":        "SELECT 1",
			"read_only":        true,
		},
	})
	if res["ok"] != false {
		t.Fatalf("expected ok=false: %+v", res)
	}
	if res["tool"] != ToolDBQuerySnowflake {
		t.Fatalf("expected tool=%s: %+v", ToolDBQuerySnowflake, res)
	}
}
