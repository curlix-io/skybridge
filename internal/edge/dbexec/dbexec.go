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
	ToolDBQueryPostgres  = "db_query_postgres"
	ToolDBQueryMySQL     = "db_query_mysql"
	ToolDBQueryMongo     = "db_query_mongo"
	ToolDBQuerySnowflake = "db_query_snowflake"
	// ToolDBQueryNeo4j runs a read-only Cypher statement against the customer-hosted Asset
	// Inventory graph (an EFS-backed ECS Fargate Neo4j task provisioned by CreateAssetInventory in
	// the sibling curlix repo's curlix-skybridge.yaml, co-located with this connector). Same
	// request/response shape as the other db_query_* tools below — see run()'s "neo4j" branch and
	// resolveNeo4jTarget's env-var fallback for how its connection target is resolved.
	ToolDBQueryNeo4j = "db_query_neo4j"

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
	// IdempotencyTTL / IdempotencyMaxEntries bound runWrite's idempotency-key cache (see
	// idempotency.go). Zero/negative values fall back to defaultIdempotencyTTL /
	// defaultIdempotencyMaxEntries in newIdempotencyCache.
	IdempotencyTTL        time.Duration
	IdempotencyMaxEntries int
	// Neo4jStaticURI is the last-resort fallback for resolving where the co-located Asset Inventory
	// Neo4j task lives (SKYBRIDGE_ASSET_INVENTORY_NEO4J_URI, e.g. "bolt://localhost:7687") — used by
	// runNeo4j only when neither a per-call "connection" override nor a matching entry in Targets
	// resolves a target, since that graph is provisioned alongside this connector rather than
	// requiring a customer-configured static Targets/SKYBRIDGE_STUDIO_TARGETS entry per deploy. See
	// resolveNeo4jTarget.
	Neo4jStaticURI string
}

// Executor runs one-shot DB statements for POST /studio/exec (Design B).
type Executor struct {
	opts Options
	idem *idempotencyCache
}

// New builds an Executor with defaults applied.
func New(opts Options) Executor {
	if opts.MaxRows <= 0 {
		opts.MaxRows = 1000
	}
	if opts.QueryTimeout <= 0 {
		opts.QueryTimeout = 60 * time.Second
	}
	return Executor{
		opts: opts,
		idem: newIdempotencyCache(opts.IdempotencyTTL, opts.IdempotencyMaxEntries),
	}
}

// Register wires db_query_{postgres,mysql,mongo,snowflake,neo4j} and db_execute_write into the
// edge registry.
func Register(reg *edge.Registry, opts Options) {
	e := New(opts)
	reg.Register(ToolDBQueryPostgres, e.runPostgres)
	reg.Register(ToolDBQueryMySQL, e.runMySQL)
	reg.Register(ToolDBQueryMongo, e.runMongo)
	reg.Register(ToolDBQuerySnowflake, e.runSnowflake)
	reg.Register(ToolDBQueryNeo4j, e.runNeo4j)
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

func (e Executor) runSnowflake(ctx context.Context, args map[string]any) (edge.Result, error) {
	return e.run(ctx, "snowflake", args)
}

func (e Executor) runNeo4j(ctx context.Context, args map[string]any) (edge.Result, error) {
	return e.run(ctx, "neo4j", args)
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

	target, ok := resolveTarget(e.opts.Targets, dbType, scope, database, args)
	if !ok && dbType == "neo4j" {
		target, ok = resolveNeo4jStaticTarget(e.opts.Neo4jStaticURI, database)
	}
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
//
// A "dry_run" arg (default false) short-circuits before dbquery.Execute: the target/args are still
// resolved and validated (so a genuine "no local target" error still surfaces), but no statement
// ever reaches the database. Mirrors studiotransport's existing ExecuteAssignment.DryRun behavior
// for the Studio Gateway session path — this is the equivalent for the Connector Gateway dispatch
// path db_execute_write runs on.
func (e Executor) runWrite(ctx context.Context, args map[string]any) (edge.Result, error) {
	dbType := strArg(args, "db_type")
	database := strArg(args, "database")
	scope := strArg(args, "connection_scope")
	statement := strArg(args, "statement")
	if dbType == "" || database == "" || statement == "" {
		return edge.ErrorResult(ToolDBExecuteWrite, "db_type, database and statement are required"), nil
	}

	// Idempotency-Key (see idempotency.go and root CLAUDE.md's "dry_run + Idempotency-Key on
	// sensitive writes" rule): a retry carrying the same key as a prior successful call returns
	// that call's result without re-executing — checked before target resolution so a cache hit
	// never depends on the target still being resolvable. Absent key skips this entirely — dedup
	// is opt-in per call, not a default the caller can't turn off.
	idemKey := strArg(args, "idempotency_key")
	var idemHash string
	if idemKey != "" {
		idemHash = requestHash(dbType, database, statement)
		if cached, hit, conflict := e.idem.get(idemKey, idemHash); hit {
			return cached, nil
		} else if conflict {
			return edge.ErrorResult(ToolDBExecuteWrite, "idempotency_key reused with a different db_type/database/statement"), nil
		}
	}

	target, ok := resolveTarget(e.opts.Targets, dbType, scope, database, args)
	if !ok {
		return edge.ErrorResult(ToolDBExecuteWrite, fmt.Sprintf("no local target for %s/%s/%s", dbType, scope, database)), nil
	}

	if boolArg(args, "dry_run", false) {
		return edge.Result{
			"ok":     true,
			"tool":   ToolDBExecuteWrite,
			"status": "dry_run",
			"results": map[string]any{
				"message": "validated locally, not executed",
			},
		}, nil
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
	result := edge.Result{
		"ok":      true,
		"tool":    ToolDBExecuteWrite,
		"results": results,
	}
	if idemKey != "" {
		e.idem.put(idemKey, idemHash, result)
	}
	return result, nil
}

// resolveTarget prefers a per-call "connection" override (see dbquery.TargetFromOverride) pushed
// alongside the dispatch over the connector's static Targets list — this is what lets a database
// the control plane resolved fresh (e.g. one added after the connector's last deploy, or one
// identified by a Data-sources connection name rather than a static aws_account_id/database_name
// pair) actually work, instead of always requiring a matching static-target entry. Falls back to
// dbquery.Resolve when no valid override is present, so a connector relying purely on static
// Targets/SKYBRIDGE_STUDIO_TARGETS config is unaffected.
func resolveTarget(targets []dbquery.Target, dbType, scope, database string, args map[string]any) (dbquery.Target, bool) {
	if conn, ok := args["connection"].(map[string]any); ok {
		if t, ok := dbquery.TargetFromOverride(dbType, database, conn); ok {
			return t, true
		}
	}
	return dbquery.Resolve(targets, dbType, scope, database)
}

// resolveNeo4jStaticTarget is the last-resort fallback used by run() for dbType "neo4j" once
// resolveTarget (dynamic "connection" override, then the static Targets list) has already come up
// empty. staticURI is Options.Neo4jStaticURI (SKYBRIDGE_ASSET_INVENTORY_NEO4J_URI), a plain
// "bolt://host:port" (or "neo4j://..."/"bolt+s://...") value describing the connector's
// co-located Asset Inventory task — carried through as dbquery.Target.DSN so executeNeo4j's
// neo4jURI uses it verbatim rather than trying to decompose it into Host. Returns ok=false when
// staticURI is empty, matching resolveTarget's own "fall through to no target" contract.
func resolveNeo4jStaticTarget(staticURI, database string) (dbquery.Target, bool) {
	staticURI = strings.TrimSpace(staticURI)
	if staticURI == "" {
		return dbquery.Target{}, false
	}
	return dbquery.Target{DBType: "neo4j", DatabaseName: database, DSN: staticURI}, true
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
