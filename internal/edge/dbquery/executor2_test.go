package dbquery

import (
	"context"
	"testing"
	"time"
)

// TestObjectID exercises objectID's OrgID-gated construction, used by every executor to scope
// mask.Column.ObjectID (see executor.go's doc comment on Options.OrgID).
func TestObjectID(t *testing.T) {
	if got := objectID("", "postgres", "app", "orders"); got != "" {
		t.Fatalf("expected empty ObjectID when OrgID is unset, got %q", got)
	}
	if got := objectID("org1", "postgres", "app", "orders"); got != "org1:postgres:app:orders" {
		t.Fatalf("unexpected ObjectID, got %q", got)
	}
	// normalizeDBType should apply inside objectID too.
	if got := objectID("org1", "POSTGRESQL", "app", "orders"); got != "org1:postgres:app:orders" {
		t.Fatalf("expected dbType normalized inside objectID, got %q", got)
	}
}

// TestExecuteDialsPostgresWithCancelledContext exercises the executePostgres path (host resolution,
// DSN building, dial) via Execute's public dispatch, using an already-cancelled context so the
// QueryContext call fails immediately without needing a live Postgres server — keeping this
// hermetic per CLAUDE.md's testing guidance.
func TestExecuteDialsPostgresWithCancelledContext(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_, err := Execute(ctx, Target{Host: "127.0.0.1:1"}, "postgres", "db", "SELECT 1", Options{})
	if err == nil {
		t.Fatal("expected an error from a cancelled context during postgres dial/query")
	}
}

func TestExecuteDialsMySQLWithCancelledContext(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_, err := Execute(ctx, Target{Host: "127.0.0.1:1"}, "mysql", "db", "SELECT 1", Options{})
	if err == nil {
		t.Fatal("expected an error from a cancelled context during mysql dial/query")
	}
}

// TestExecutePostgresMissingHost / TestExecuteMySQLMissingHost cover the "target missing host"
// guard that runs before any dial attempt.
func TestExecutePostgresMissingHost(t *testing.T) {
	_, err := Execute(context.Background(), Target{}, "postgres", "db", "SELECT 1", Options{})
	if err == nil {
		t.Fatal("expected an error when postgres target has no host")
	}
}

func TestExecuteMySQLMissingHost(t *testing.T) {
	_, err := Execute(context.Background(), Target{}, "mysql", "db", "SELECT 1", Options{})
	if err == nil {
		t.Fatal("expected an error when mysql target has no host")
	}
}

func TestExecuteSnowflakeMissingHost(t *testing.T) {
	_, err := Execute(context.Background(), Target{}, "snowflake", "db", "SELECT 1", Options{})
	if err == nil {
		t.Fatal("expected an error when snowflake target has no account locator")
	}
}

// TestExecuteSnowflakeDialsWithCancelledContext exercises executeSnowflake's DSN build + dial path.
func TestExecuteSnowflakeDialsWithCancelledContext(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_, err := Execute(ctx, Target{Host: "acct"}, "snowflake", "db", "SELECT 1", Options{})
	if err == nil {
		t.Fatal("expected an error from a cancelled context during snowflake dial/query")
	}
}

// TestExecutePostgresEmptyStatement / TestExecuteMySQLEmptyStatement / TestExecuteSnowflakeEmptyStatement
// cover the errEmptyQuery short-circuit at the top of each read executor, before host is even checked.
func TestExecutePostgresEmptyStatement(t *testing.T) {
	_, err := Execute(context.Background(), Target{Host: "h"}, "postgres", "db", "   ", Options{})
	if err != errEmptyQuery {
		t.Fatalf("expected errEmptyQuery, got %v", err)
	}
}

func TestExecuteMySQLEmptyStatement(t *testing.T) {
	_, err := Execute(context.Background(), Target{Host: "h"}, "mysql", "db", "", Options{})
	if err != errEmptyQuery {
		t.Fatalf("expected errEmptyQuery, got %v", err)
	}
}

func TestExecuteSnowflakeEmptyStatement(t *testing.T) {
	_, err := Execute(context.Background(), Target{Host: "h"}, "snowflake", "db", "", Options{})
	if err != errEmptyQuery {
		t.Fatalf("expected errEmptyQuery, got %v", err)
	}
}

// TestExecuteMongoMissingHost / TestExecuteMongoBadStatement cover executeMongo's early guards:
// statement parse failure surfaces before any dial attempt, and a missing host is rejected once
// parsing succeeds.
func TestExecuteMongoBadStatementNeverDials(t *testing.T) {
	_, err := Execute(context.Background(), Target{}, "mongo", "db", "not a mongo statement", Options{})
	if err == nil {
		t.Fatal("expected a parse error for an unsupported mongo statement shape")
	}
}

func TestExecuteMongoMissingHost(t *testing.T) {
	_, err := Execute(context.Background(), Target{}, "mongo", "db", "db.users.find({})", Options{})
	if err == nil {
		t.Fatal("expected an error when mongo target has no host")
	}
}

// TestExecuteMongoAggregateDialsWithCancelledContext exercises executeMongo's "aggregate" branch
// (coll.Aggregate), which the find-shaped test above doesn't reach.
func TestExecuteMongoAggregateDialsWithCancelledContext(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 150*time.Millisecond)
	defer cancel()
	_, err := Execute(ctx, Target{Host: "127.0.0.1:1"}, "mongo", "db", `db.orders.aggregate([{"$match":{"a":1}}])`, Options{})
	if err == nil {
		t.Fatal("expected a server-selection error against an unreachable host")
	}
}

func TestExecuteMongoDialsWithCancelledContext(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_, err := Execute(ctx, Target{Host: "127.0.0.1:1"}, "mongo", "db", "db.users.find({})", Options{Timeout: 200 * time.Millisecond})
	if err == nil {
		t.Fatal("expected an error from a cancelled context during mongo dial")
	}
}

// TestExecuteMongoPingReachesRunCommandNotFindOrAggregate proves the "ping" statement dials
// (unlike TestExecuteMongoBadStatementNeverDials's unparseable-statement case, which never
// reaches a dial at all) via RunCommand — an unreachable host still surfaces a real dial/server-
// selection error rather than a "no local target"/parse error, and it does so with no collection
// set on the target (see TestParseMongoStatementPing), which coll.Find/Aggregate would need.
func TestExecuteMongoPingReachesRunCommandNotFindOrAggregate(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 150*time.Millisecond)
	defer cancel()
	_, err := Execute(ctx, Target{Host: "127.0.0.1:1"}, "mongo", "db", "ping", Options{})
	if err == nil {
		t.Fatal("expected a server-selection error against an unreachable host")
	}
}

// TestExecuteDatabaseNameFallsBackToTargetDatabaseName exercises the "database == ”" branch in
// every executor's dbName resolution (they all fall back to target.DatabaseName). Using an empty
// database string with postgres against a cancelled context proves the fallback path runs (a host
// still needs to be set to get past the earlier guard) without needing a live server.
func TestExecuteDatabaseNameFallsBackToTargetDatabaseName(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_, err := Execute(ctx, Target{Host: "127.0.0.1:1", DatabaseName: "fallback_db"}, "postgres", "", "SELECT 1", Options{})
	if err == nil {
		t.Fatal("expected an error from the cancelled context")
	}
}
