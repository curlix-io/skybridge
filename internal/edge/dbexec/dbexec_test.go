//go:build querystudio

package dbexec

import (
	"context"
	"testing"

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
	for _, name := range []string{ToolDBQueryPostgres, ToolDBQueryMySQL, ToolDBQueryMongo} {
		if !reg.Has(name) {
			t.Fatalf("missing %s", name)
		}
	}
}
