package dbquery

import (
	"context"
	"strings"
	"testing"
	"time"
)

func TestMigrationOptionsWithDefaults(t *testing.T) {
	o := MigrationOptions{}.withDefaults()
	if o.Timeout != 60*time.Second {
		t.Fatalf("expected default 60s timeout, got %v", o.Timeout)
	}
	o2 := MigrationOptions{Timeout: 5 * time.Second}.withDefaults()
	if o2.Timeout != 5*time.Second {
		t.Fatalf("expected explicit timeout preserved, got %v", o2.Timeout)
	}
}

func TestExecuteMigrationRejectsMongo(t *testing.T) {
	_, err := ExecuteMigration(context.Background(), Target{Host: "h"}, "mongo", "db", []string{"db.x.insert({})"}, MigrationOptions{})
	if err != ErrMongoMigrationUnsupported {
		t.Fatalf("expected ErrMongoMigrationUnsupported, got %v", err)
	}
	// mongodb alias should also be rejected.
	_, err = ExecuteMigration(context.Background(), Target{Host: "h"}, "mongodb", "db", []string{"db.x.insert({})"}, MigrationOptions{})
	if err != ErrMongoMigrationUnsupported {
		t.Fatalf("expected ErrMongoMigrationUnsupported for mongodb alias, got %v", err)
	}
}

func TestExecuteMigrationRejectsUnsupportedDBType(t *testing.T) {
	_, err := ExecuteMigration(context.Background(), Target{Host: "h"}, "oracle", "db", []string{"SELECT 1"}, MigrationOptions{})
	if err == nil {
		t.Fatal("expected an error for an unsupported db_type")
	}
}

// TestExecuteMigrationPostgresDialsWithCancelledContext exercises the postgres branch of
// ExecuteMigration (postgresDSN + execMigrationSQL's sql.Open/BeginTx) without a live server: the
// cancelled context makes BeginTx fail fast, which is enough to exercise execMigrationSQL's error
// path without a mock driver.
func TestExecuteMigrationPostgresDialsWithCancelledContext(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	res, err := ExecuteMigration(ctx, Target{Host: "127.0.0.1:1"}, "postgres", "db", []string{"CREATE TABLE t (x int)"}, MigrationOptions{})
	if err == nil {
		t.Fatal("expected an error from the cancelled context")
	}
	if res.AppliedStatements != 0 {
		t.Fatalf("expected 0 applied statements, got %d", res.AppliedStatements)
	}
}

func TestExecuteMigrationMySQLDialsWithCancelledContext(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_, err := ExecuteMigration(ctx, Target{Host: "127.0.0.1:1"}, "mysql", "db", []string{"CREATE TABLE t (x int)"}, MigrationOptions{})
	if err == nil {
		t.Fatal("expected an error from the cancelled context")
	}
}

func TestExecuteMigrationSnowflakeDialsWithCancelledContext(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	// User/Password set so snowflakeDSN itself succeeds and the failure surfaces from
	// execMigrationSQL's cancelled-context dial (line 66's happy branch into execMigrationSQL),
	// not from fillMissingConfigParameters' "empty username" guard.
	_, err := ExecuteMigration(ctx, Target{Host: "acct", User: "u", Password: "p"}, "snowflake", "db", []string{"CREATE TABLE t (x int)"}, MigrationOptions{})
	if err == nil {
		t.Fatal("expected an error from the cancelled context")
	}
}

func TestExecMigrationSQLRejectsEmptyStatements(t *testing.T) {
	_, err := execMigrationSQL(context.Background(), "pgx", "postgres://u:p@127.0.0.1:1/db?sslmode=disable", nil)
	if err != errEmptyQuery {
		t.Fatalf("expected errEmptyQuery, got %v", err)
	}
}

// TestExecMigrationSQLSkipsBlankStatements confirms blank entries in the statements slice are
// skipped (continue) rather than executed or counted, before the whole thing fails on a real dial
// attempt against a cancelled context (statements list must be non-empty to get past the guard, but
// only the non-blank one should ever reach ExecContext).
func TestExecMigrationSQLSkipsBlankStatementsListNotEmpty(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	res, err := execMigrationSQL(ctx, "pgx", "postgres://u:p@127.0.0.1:1/db?sslmode=disable", []string{"   ", "CREATE TABLE t (x int)"})
	if err == nil {
		t.Fatal("expected an error since the context is already cancelled")
	}
	if res.AppliedStatements != 0 {
		t.Fatalf("expected 0 applied statements, got %d", res.AppliedStatements)
	}
}

func TestPostgresDSNUsesDefaultSSLMode(t *testing.T) {
	dsn := postgresDSN(Target{Host: "h", User: "u", Password: "p"}, "db", MigrationOptions{})
	if dsn != "postgres://u:p@h/db?sslmode=require" {
		t.Fatalf("unexpected dsn: %q", dsn)
	}
}

func TestPostgresDSNRespectsTargetSSLMode(t *testing.T) {
	dsn := postgresDSN(Target{Host: "h", User: "u", Password: "p", SSLMode: "disable"}, "db", MigrationOptions{})
	if dsn != "postgres://u:p@h/db?sslmode=disable" {
		t.Fatalf("unexpected dsn: %q", dsn)
	}
}

func TestPostgresDSNFallsBackToTargetDatabaseName(t *testing.T) {
	dsn := postgresDSN(Target{Host: "h", User: "u", Password: "p", DatabaseName: "fallback"}, "", MigrationOptions{})
	if dsn != "postgres://u:p@h/fallback?sslmode=require" {
		t.Fatalf("unexpected dsn: %q", dsn)
	}
}

func TestMySQLDSNFallsBackToTargetDatabaseName(t *testing.T) {
	dsn := mysqlDSN(Target{Host: "h:3306", User: "u", Password: "p", DatabaseName: "fallback"}, "", MigrationOptions{})
	if dsn != "u:p@tcp(h:3306)/fallback?parseTime=true&timeout=30s" {
		t.Fatalf("unexpected dsn: %q", dsn)
	}
}

func TestSnowflakeDSNFallsBackToTargetDatabaseName(t *testing.T) {
	dsn, err := snowflakeDSN(Target{Host: "acct", User: "u", Password: "p", DatabaseName: "fallback"}, "", MigrationOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if dsn == "" {
		t.Fatal("expected a non-empty DSN")
	}
}

// TestExecMigrationSQLRejectsUnknownDriver exercises execMigrationSQL's sql.Open error branch: a
// driver name that was never sql.Register'd fails immediately, before any BeginTx attempt.
func TestExecMigrationSQLRejectsUnknownDriver(t *testing.T) {
	_, err := execMigrationSQL(context.Background(), "no-such-driver-registered", "dsn", []string{"CREATE TABLE t (x int)"})
	if err == nil {
		t.Fatal("expected an error for an unregistered driver name")
	}
}

// TestExecMigrationSQLSkipsBlankStatementsAmongReal exercises the "continue" branch for a blank
// statement sitting between two real ones, against a live (fake) driver that actually commits —
// AppliedStatements must count only the two real statements, not the blank one.
func TestExecMigrationSQLSkipsBlankStatementsAmongReal(t *testing.T) {
	driverName := registerFakeSQLDriver(false)
	res, err := execMigrationSQL(context.Background(), driverName, "fake-dsn", []string{"CREATE TABLE t (x int)", "   ", "INSERT INTO t VALUES (1)"})
	if err != nil {
		t.Fatal(err)
	}
	if res.AppliedStatements != 2 {
		t.Fatalf("expected 2 applied statements (blank skipped), got %d", res.AppliedStatements)
	}
}

func TestMySQLDSNBuildsExpectedForm(t *testing.T) {
	dsn := mysqlDSN(Target{Host: "h:3306", User: "u", Password: "p"}, "db", MigrationOptions{})
	if dsn != "u:p@tcp(h:3306)/db?parseTime=true&timeout=30s" {
		t.Fatalf("unexpected dsn: %q", dsn)
	}
}

func TestSnowflakeDSNBuildsExpectedForm(t *testing.T) {
	dsn, err := snowflakeDSN(Target{Host: "acct", User: "u", Password: "p", Warehouse: "wh", Role: "role", Schema: "schema"}, "db", MigrationOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if dsn == "" {
		t.Fatal("expected a non-empty DSN")
	}
}

// TestExecMigrationSQLCommitsAllStatements exercises execMigrationSQL's full happy path (multiple
// statements, all succeed, tx.Commit succeeds) against fakeSQLDriver, hermetically.
func TestExecMigrationSQLCommitsAllStatements(t *testing.T) {
	driverName := registerFakeSQLDriver(false)
	res, err := execMigrationSQL(context.Background(), driverName, "fake-dsn", []string{"CREATE TABLE t (x int)", "INSERT INTO t VALUES (1)"})
	if err != nil {
		t.Fatal(err)
	}
	if res.AppliedStatements != 2 {
		t.Fatalf("expected 2 applied statements, got %d", res.AppliedStatements)
	}
}

// TestExecMigrationSQLRollsBackOnStatementFailure exercises the mid-changeset failure branch: the
// first statement succeeds, the second (containing "FAIL") fails, and rollback itself succeeds —
// AppliedStatements must report only the count that committed before the failure.
func TestExecMigrationSQLRollsBackOnStatementFailure(t *testing.T) {
	driverName := registerFakeSQLDriver(false)
	res, err := execMigrationSQL(context.Background(), driverName, "fake-dsn", []string{"CREATE TABLE t (x int)", "FAIL THIS ONE", "INSERT INTO t VALUES (1)"})
	if err == nil {
		t.Fatal("expected an error from the failing statement")
	}
	if res.AppliedStatements != 1 {
		t.Fatalf("expected 1 applied statement before the failure, got %d", res.AppliedStatements)
	}
}

// TestExecMigrationSQLReportsBothFailuresWhenRollbackAlsoFails exercises the compound-failure
// branch: the statement fails AND the subsequent rollback also fails, which must surface both
// errors together rather than swallowing the rollback failure.
func TestExecMigrationSQLReportsBothFailuresWhenRollbackAlsoFails(t *testing.T) {
	driverName := registerFakeSQLDriverFull(false, true)
	res, err := execMigrationSQL(context.Background(), driverName, "fake-dsn", []string{"FAIL THIS ONE"})
	if err == nil {
		t.Fatal("expected an error")
	}
	if !strings.Contains(err.Error(), "rollback also failed") {
		t.Fatalf("expected the rollback failure to be reported too, got %v", err)
	}
	if res.AppliedStatements != 0 {
		t.Fatalf("expected 0 applied statements, got %d", res.AppliedStatements)
	}
}

// TestExecMigrationSQLFailsOnCommit exercises the tx.Commit failure branch: every statement
// succeeds, but Commit itself fails.
func TestExecMigrationSQLFailsOnCommit(t *testing.T) {
	driverName := registerFakeSQLDriver(true)
	res, err := execMigrationSQL(context.Background(), driverName, "fake-dsn", []string{"CREATE TABLE t (x int)"})
	if err == nil {
		t.Fatal("expected a commit failure")
	}
	if res.AppliedStatements != 1 {
		t.Fatalf("expected 1 applied statement despite the commit failure, got %d", res.AppliedStatements)
	}
}
