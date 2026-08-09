//go:build querystudio

package dbexec

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/curlix-io/skybridge/internal/edge"
	"github.com/curlix-io/skybridge/internal/edge/dbquery"
	"github.com/curlix-io/skybridge/internal/mask"
)

const (
	ToolDBQueryPostgres = "db_query_postgres"
	ToolDBQueryMySQL    = "db_query_mysql"
	ToolDBQueryMongo    = "db_query_mongo"

	// ToolDBExecuteWrite is a distinct write-capable tool, separate from the always-read-only
	// db_query_* tools above (whose EnforceReadOnly:true in run() never changes). Whether a given
	// statement should be allowed here is Curlix's own allow/deny decision made before dispatch —
	// this handler runs whatever statement it's given, unmodified, via dbquery's write path
	// (ExecContext for SQL, direct CRUD/aggregate calls for Mongo). See internal/edge/dbquery/write.go.
	ToolDBExecuteWrite = "db_execute_write"
)

// Options configures db_query_* handlers on the connector edge.
type Options struct {
	Targets          []dbquery.Target
	FallbackUser     string
	FallbackPassword string
	Masker           mask.Masker
	MaxRows          int
	QueryTimeout     time.Duration
	// OrgID scopes path-/table-aware masking labels (see dbquery.Options.OrgID). Empty disables
	// that scoping without otherwise affecting masking.
	OrgID string
}

// Executor runs one-shot DB statements for POST /studio/exec (Design B).
type Executor struct {
	opts Options
}

// New builds an Executor with defaults applied.
func New(opts Options) Executor {
	if opts.MaxRows <= 0 {
		opts.MaxRows = 1000
	}
	if opts.QueryTimeout <= 0 {
		opts.QueryTimeout = 60 * time.Second
	}
	return Executor{opts: opts}
}

// Register wires db_query_{postgres,mysql,mongo} and db_execute_write into the edge registry.
func Register(reg *edge.Registry, opts Options) {
	e := New(opts)
	reg.Register(ToolDBQueryPostgres, e.runPostgres)
	reg.Register(ToolDBQueryMySQL, e.runMySQL)
	reg.Register(ToolDBQueryMongo, e.runMongo)
	reg.Register(ToolDBExecuteWrite, e.runWrite)
}

func (e Executor) runPostgres(ctx context.Context, args map[string]any) (edge.Result, error) {
	return e.run(ctx, "postgres", args)
}

func (e Executor) runMySQL(ctx context.Context, args map[string]any) (edge.Result, error) {
	return e.run(ctx, "mysql", args)
}

func (e Executor) runMongo(ctx context.Context, args map[string]any) (edge.Result, error) {
	return e.run(ctx, "mongo", args)
}

func (e Executor) run(ctx context.Context, dbType string, args map[string]any) (edge.Result, error) {
	database := strArg(args, "database")
	scope := strArg(args, "connection_scope")
	statement := strArg(args, "statement")
	if database == "" || statement == "" {
		return edge.ErrorResult(toolName(dbType), "database and statement are required"), nil
	}
	readOnly := boolArg(args, "read_only", true)
	maxRows := intArg(args, "max_rows", e.opts.MaxRows)

	target, ok := dbquery.Resolve(e.opts.Targets, dbType, scope, database)
	if !ok {
		return edge.ErrorResult(toolName(dbType), fmt.Sprintf("no local target for %s/%s/%s", dbType, scope, database)), nil
	}

	raw, err := dbquery.Execute(ctx, target, dbType, database, statement, dbquery.Options{
		FallbackUser:     e.opts.FallbackUser,
		FallbackPassword: e.opts.FallbackPassword,
		Masker:           e.opts.Masker,
		ApplyPII:         true,
		MaxRows:          maxRows,
		Timeout:          e.opts.QueryTimeout,
		EnforceReadOnly:  readOnly,
		OrgID:            e.opts.OrgID,
	})
	if err != nil {
		return edge.ErrorResult(toolName(dbType), err.Error()), nil
	}

	rows := extractRows(raw)
	return edge.Result{
		"ok":        true,
		"tool":      toolName(dbType),
		"result":    rows,
		"row_count": len(rows),
	}, nil
}

// runWrite executes a write statement dispatched to db_execute_write. Unlike run() above, it does
// not apply PII masking (there's no result set to mask on most writes) and never sets
// EnforceReadOnly — the statement runs exactly as given via dbquery.Options{Write: true}. Curlix's
// allow/deny decision, made before this call was dispatched, is the only gate; the edge does not
// re-derive it from the statement's shape.
func (e Executor) runWrite(ctx context.Context, args map[string]any) (edge.Result, error) {
	dbType := strArg(args, "db_type")
	database := strArg(args, "database")
	scope := strArg(args, "connection_scope")
	statement := strArg(args, "statement")
	if dbType == "" || database == "" || statement == "" {
		return edge.ErrorResult(ToolDBExecuteWrite, "db_type, database and statement are required"), nil
	}

	target, ok := dbquery.Resolve(e.opts.Targets, dbType, scope, database)
	if !ok {
		return edge.ErrorResult(ToolDBExecuteWrite, fmt.Sprintf("no local target for %s/%s/%s", dbType, scope, database)), nil
	}

	raw, err := dbquery.Execute(ctx, target, dbType, database, statement, dbquery.Options{
		FallbackUser:     e.opts.FallbackUser,
		FallbackPassword: e.opts.FallbackPassword,
		Timeout:          e.opts.QueryTimeout,
		Write:            true,
		OrgID:            e.opts.OrgID,
	})
	if err != nil {
		return edge.ErrorResult(ToolDBExecuteWrite, err.Error()), nil
	}

	results, _ := raw["results"].(map[string]any)
	return edge.Result{
		"ok":      true,
		"tool":    ToolDBExecuteWrite,
		"results": results,
	}, nil
}

func toolName(dbType string) string {
	if dbType == "mongo" {
		return ToolDBQueryMongo
	}
	return "db_query_" + dbType
}

func extractRows(raw map[string]any) []map[string]any {
	if res, ok := raw["results"].(map[string]any); ok {
		if data, ok := res["data"].([]map[string]any); ok {
			return data
		}
		if data, ok := res["data"].([]any); ok {
			out := make([]map[string]any, 0, len(data))
			for _, row := range data {
				if m, ok := row.(map[string]any); ok {
					out = append(out, m)
				}
			}
			return out
		}
	}
	return nil
}

func strArg(args map[string]any, key string) string {
	v, ok := args[key]
	if !ok || v == nil {
		return ""
	}
	return strings.TrimSpace(fmt.Sprint(v))
}

func boolArg(args map[string]any, key string, def bool) bool {
	v, ok := args[key]
	if !ok || v == nil {
		return def
	}
	switch x := v.(type) {
	case bool:
		return x
	case string:
		switch strings.ToLower(strings.TrimSpace(x)) {
		case "1", "true", "yes", "on":
			return true
		case "0", "false", "no", "off":
			return false
		}
	}
	return def
}

func intArg(args map[string]any, key string, def int) int {
	v, ok := args[key]
	if !ok || v == nil {
		return def
	}
	switch x := v.(type) {
	case int:
		return x
	case int64:
		return int(x)
	case float64:
		return int(x)
	case string:
		var n int
		if _, err := fmt.Sscanf(strings.TrimSpace(x), "%d", &n); err == nil && n > 0 {
			return n
		}
	}
	return def
}
