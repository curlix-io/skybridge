//go:build querystudio

package dbexec

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/curlix-io/skybridge/internal/edge"
	"github.com/curlix-io/skybridge/internal/edge/dbquery"
)

// ToolDBExecMigration is the write-capable, changeset-oriented counterpart to db_query_* — it has
// no read_only knob (the tool name itself is the write signal) and applies a full solidbase
// changeset atomically instead of one read statement per call.
const ToolDBExecMigration = "db_exec_migration"

// MigrationOptions configures the db_exec_migration handler.
type MigrationOptions struct {
	Targets          []dbquery.Target
	FallbackUser     string
	FallbackPassword string
	Timeout          time.Duration
	MongoshBin       string // override for tests; defaults to findMongoshPath()
}

// MigrationResult mirrors dbquery.MigrationResult so the SQL and Mongo paths share one result shape.
type MigrationResult = dbquery.MigrationResult

// migrationExecutor runs db_exec_migration for one configured set of targets.
type migrationExecutor struct {
	opts MigrationOptions
}

// RegisterMigration wires db_exec_migration into the edge registry, alongside the existing
// db_query_* tools registered by Register (dbexec.go). Kept as a separate entry point (rather than
// folded into Register) so callers can enable/disable the write-capable tool independently — e.g.
// while solidbase's wire-edge dispatch is being rolled out behind CURLIX_SOLIDBASE_APPLY_VIA_WIRE_EDGE
// on the curlix side.
func RegisterMigration(reg *edge.Registry, opts MigrationOptions) {
	e := migrationExecutor{opts: opts}
	reg.Register(ToolDBExecMigration, e.run)
}

func (e migrationExecutor) run(ctx context.Context, args map[string]any) (edge.Result, error) {
	database := strArg(args, "database")
	scope := strArg(args, "connection_scope")
	dbType := strArg(args, "db_type")
	statements := stringListArg(args, "statements")
	if database == "" || dbType == "" || len(statements) == 0 {
		return edge.ErrorResult(ToolDBExecMigration, "database, db_type, and a non-empty statements list are required"), nil
	}

	target, ok := dbquery.Resolve(e.opts.Targets, dbType, scope, database)
	if !ok {
		return edge.ErrorResult(ToolDBExecMigration, fmt.Sprintf("no local target for %s/%s/%s", dbType, scope, database)), nil
	}

	if strings.EqualFold(strings.TrimSpace(dbType), "mongo") || strings.EqualFold(strings.TrimSpace(dbType), "mongodb") {
		res, err := runMongoMigration(ctx, target, database, strings.Join(statements, "\n"), mongoMigrationOptions{
			MongoshBin: e.opts.MongoshBin,
			Timeout:    e.opts.Timeout,
		})
		return migrationResultToEdgeResult(res, err)
	}

	res, err := dbquery.ExecuteMigration(ctx, target, dbType, database, statements, dbquery.MigrationOptions{
		FallbackUser:     e.opts.FallbackUser,
		FallbackPassword: e.opts.FallbackPassword,
		Timeout:          e.opts.Timeout,
	})
	return migrationResultToEdgeResult(res, err)
}

func migrationResultToEdgeResult(res MigrationResult, err error) (edge.Result, error) {
	if err != nil {
		return edge.Result{
			"ok":                 false,
			"tool":               ToolDBExecMigration,
			"applied_statements": res.AppliedStatements,
			"error":              err.Error(),
		}, nil
	}
	return edge.Result{
		"ok":                 true,
		"tool":               ToolDBExecMigration,
		"applied_statements": res.AppliedStatements,
	}, nil
}

func stringListArg(args map[string]any, key string) []string {
	v, ok := args[key]
	if !ok || v == nil {
		return nil
	}
	switch x := v.(type) {
	case []string:
		return x
	case []any:
		out := make([]string, 0, len(x))
		for _, item := range x {
			s := strings.TrimSpace(fmt.Sprint(item))
			if s != "" {
				out = append(out, s)
			}
		}
		return out
	case string:
		s := strings.TrimSpace(x)
		if s == "" {
			return nil
		}
		return []string{s}
	default:
		return nil
	}
}
