package dbquery

import (
	"context"
	"database/sql"
	"database/sql/driver"
	"fmt"
	"strings"
	"sync"
)

// fakeSQLDriver is a minimal in-memory database/sql driver used to exercise execMigrationSQL's
// commit/rollback branches hermetically (no real Postgres/MySQL/Snowflake server). Statements
// whose text contains "FAIL" fail on ExecContext; a driver name registered with failCommit=true
// fails on transaction Commit instead. Registration is keyed by a unique DSN so parallel tests don't
// collide on shared driver-level state (sql.Register itself is process-global and can only be
// called once per driver name).
type fakeSQLDriver struct {
	mu           sync.Mutex
	failCommit   bool
	failRollback bool
}

func (d *fakeSQLDriver) Open(name string) (driver.Conn, error) {
	return &fakeSQLConn{driver: d}, nil
}

type fakeSQLConn struct {
	driver *fakeSQLDriver
}

func (c *fakeSQLConn) Prepare(query string) (driver.Stmt, error) {
	return nil, fmt.Errorf("fakeSQLConn: Prepare not supported, use ExecContext")
}
func (c *fakeSQLConn) Close() error { return nil }
func (c *fakeSQLConn) Begin() (driver.Tx, error) {
	return &fakeSQLTx{conn: c}, nil
}

// ExecContext implements driver.ExecerContext so *sql.Tx.ExecContext routes here directly rather
// than through Prepare (which this fake doesn't support).
func (c *fakeSQLConn) ExecContext(ctx context.Context, query string, args []driver.NamedValue) (driver.Result, error) {
	if strings.Contains(query, "FAIL") {
		return nil, fmt.Errorf("fake exec failure for statement %q", query)
	}
	return driver.RowsAffected(1), nil
}

type fakeSQLTx struct {
	conn *fakeSQLConn
}

func (tx *fakeSQLTx) Commit() error {
	if tx.conn.driver.failCommit {
		return fmt.Errorf("fake commit failure")
	}
	return nil
}
func (tx *fakeSQLTx) Rollback() error {
	if tx.conn.driver.failRollback {
		return fmt.Errorf("fake rollback failure")
	}
	return nil
}

// registerFakeSQLDriver registers a uniquely-named fake driver instance and returns its name, so
// each test gets an isolated driver (sql.Register panics on a duplicate name).
var fakeDriverSeq int
var fakeDriverMu sync.Mutex

func registerFakeSQLDriver(failCommit bool) string {
	return registerFakeSQLDriverFull(failCommit, false)
}

func registerFakeSQLDriverFull(failCommit, failRollback bool) string {
	fakeDriverMu.Lock()
	fakeDriverSeq++
	name := fmt.Sprintf("fakesql%d", fakeDriverSeq)
	fakeDriverMu.Unlock()
	sql.Register(name, &fakeSQLDriver{failCommit: failCommit, failRollback: failRollback})
	return name
}
