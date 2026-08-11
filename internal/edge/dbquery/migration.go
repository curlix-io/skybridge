package dbquery

import (
	"context"
	"database/sql"
	"fmt"
	"strings"
	"time"

	_ "github.com/go-sql-driver/mysql"
	_ "github.com/jackc/pgx/v5/stdlib"
	sf "github.com/snowflakedb/gosnowflake"
)

// MigrationOptions configures ExecuteMigration. Unlike Options (used by db_query_*), there is no
// EnforceReadOnly/Masker — db_exec_migration is write-by-design (the tool name itself is the write
// signal, mirroring how solidbase gates writes via its own approval + DML-only validation) and a
// migration apply has no result rows to mask.
type MigrationOptions struct {
	FallbackUser     string
	FallbackPassword string
	Timeout          time.Duration
}

func (o MigrationOptions) withDefaults() MigrationOptions {
	if o.Timeout <= 0 {
		o.Timeout = 60 * time.Second
	}
	return o
}

// MigrationResult reports how many statements committed before success or failure.
type MigrationResult struct {
	AppliedStatements int
}

// ErrMongoMigrationUnsupported is returned for db_type "mongo" — the edge has no JS engine to run
// arbitrary native-JS Mongo changesets (only the narrow find/aggregate regex parser in mongo.go
// exists, which cannot execute writes). Mongo changesets keep using solidbase's direct-connection
// path; this is a documented gap, not a silent fallback.
var ErrMongoMigrationUnsupported = fmt.Errorf("mongo migration changesets are not supported at the edge (no JS engine); use the direct connection path")

// ExecuteMigration runs every statement in one transaction against a resolved target, committing
// only if all statements succeed. A failure at any statement rolls back the whole changeset — the
// same effective atomicity solidbase's direct single-multi-statement-string call gets today.
func ExecuteMigration(ctx context.Context, target Target, dbType, database string, statements []string, opts MigrationOptions) (MigrationResult, error) {
	opts = opts.withDefaults()
	if normalizeDBType(dbType) == "mongo" {
		return MigrationResult{}, ErrMongoMigrationUnsupported
	}
	runCtx, cancel := context.WithTimeout(ctx, opts.Timeout)
	defer cancel()

	switch normalizeDBType(dbType) {
	case "postgres":
		return execMigrationSQL(runCtx, "pgx", postgresDSN(target, database, opts), statements)
	case "mysql":
		return execMigrationSQL(runCtx, "mysql", mysqlDSN(target, database, opts), statements)
	case "snowflake":
		dsn, err := snowflakeDSN(target, database, opts)
		if err != nil {
			return MigrationResult{}, err
		}
		return execMigrationSQL(runCtx, "snowflake", dsn, statements)
	default:
		return MigrationResult{}, fmt.Errorf("unsupported db_type %q", dbType)
	}
}

func postgresDSN(target Target, database string, opts MigrationOptions) string {
	user, pass := creds(target, opts.FallbackUser, opts.FallbackPassword)
	dbName := strings.TrimSpace(database)
	if dbName == "" {
		dbName = strings.TrimSpace(target.DatabaseName)
	}
	sslmode := strings.TrimSpace(target.SSLMode)
	if sslmode == "" {
		sslmode = "require"
	}
	return fmt.Sprintf("postgres://%s:%s@%s/%s?sslmode=%s", urlEscape(user), urlEscape(pass), strings.TrimSpace(target.Host), dbName, sslmode)
}

func mysqlDSN(target Target, database string, opts MigrationOptions) string {
	user, pass := creds(target, opts.FallbackUser, opts.FallbackPassword)
	dbName := strings.TrimSpace(database)
	if dbName == "" {
		dbName = strings.TrimSpace(target.DatabaseName)
	}
	return fmt.Sprintf("%s:%s@tcp(%s)/%s?parseTime=true&timeout=30s", urlEscape(user), urlEscape(pass), strings.TrimSpace(target.Host), dbName)
}

func snowflakeDSN(target Target, database string, opts MigrationOptions) (string, error) {
	user, pass := creds(target, opts.FallbackUser, opts.FallbackPassword)
	dbName := strings.TrimSpace(database)
	if dbName == "" {
		dbName = strings.TrimSpace(target.DatabaseName)
	}
	cfg := &sf.Config{
		Account:   strings.TrimSpace(target.Host),
		User:      user,
		Password:  pass,
		Database:  dbName,
		Schema:    strings.TrimSpace(target.Schema),
		Warehouse: strings.TrimSpace(target.Warehouse),
		Role:      strings.TrimSpace(target.Role),
	}
	return sf.DSN(cfg)
}

// execMigrationSQL opens one *sql.Tx and runs every statement through it, committing only if all
// succeed. driverName selects the already-imported database/sql driver (pgx/mysql/snowflake); dsn
// is the fully-resolved connection string for that driver.
func execMigrationSQL(ctx context.Context, driverName, dsn string, statements []string) (MigrationResult, error) {
	if len(statements) == 0 {
		return MigrationResult{}, errEmptyQuery
	}
	db, err := sql.Open(driverName, dsn)
	if err != nil {
		return MigrationResult{}, err
	}
	defer db.Close()

	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		return MigrationResult{}, err
	}
	applied := 0
	for _, stmt := range statements {
		stmt = strings.TrimSpace(stmt)
		if stmt == "" {
			continue
		}
		if _, err := tx.ExecContext(ctx, stmt); err != nil {
			if rbErr := tx.Rollback(); rbErr != nil {
				return MigrationResult{AppliedStatements: applied}, fmt.Errorf("statement %d failed: %w (rollback also failed: %v)", applied+1, err, rbErr)
			}
			return MigrationResult{AppliedStatements: applied}, fmt.Errorf("statement %d failed, changeset rolled back: %w", applied+1, err)
		}
		applied++
	}
	if err := tx.Commit(); err != nil {
		return MigrationResult{AppliedStatements: applied}, fmt.Errorf("commit failed: %w", err)
	}
	return MigrationResult{AppliedStatements: applied}, nil
}
