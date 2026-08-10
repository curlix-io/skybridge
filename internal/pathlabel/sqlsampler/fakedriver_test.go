package sqlsampler

import (
	"database/sql"
	"database/sql/driver"
	"fmt"
	"io"
	"strings"
	"sync"
)

// A minimal hand-rolled database/sql/driver fake, hermetic per CLAUDE.md's testing guidance (no
// Docker, no real database) — sqlsampler's only third-party dependency is database/sql itself, so a
// stdlib-only fake keeps that property in its tests too. Registered once under a unique name per
// test file load; queryResponses is looked up by exact query string.
type fakeDriver struct {
	mu        sync.Mutex
	responses map[string]fakeResult
	failOn    map[string]bool
}

type fakeResult struct {
	cols []string
	rows [][]driver.Value
}

var (
	fakeDriverMu       sync.Mutex
	fakeDriverRegistry = map[string]*fakeDriver{}
	fakeDriverSeq      int
)

// registerFakeDB registers a fresh fake driver instance and returns a *sql.DB open against it.
func registerFakeDB() (*sql.DB, *fakeDriver) {
	fakeDriverMu.Lock()
	fakeDriverSeq++
	name := fmt.Sprintf("sqlsampler-fake-%d", fakeDriverSeq)
	fakeDriverMu.Unlock()

	fd := &fakeDriver{responses: map[string]fakeResult{}, failOn: map[string]bool{}}
	sql.Register(name, fd)
	db, err := sql.Open(name, "")
	if err != nil {
		panic(err)
	}
	return db, fd
}

func (d *fakeDriver) setResult(query string, cols []string, rows [][]driver.Value) {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.responses[normalizeQuery(query)] = fakeResult{cols: cols, rows: rows}
}

func (d *fakeDriver) setFail(query string) {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.failOn[normalizeQuery(query)] = true
}

// normalizeQuery collapses whitespace so tests can match queries without caring about exact
// spacing produced by fmt.Sprintf in sqlsampler.go.
func normalizeQuery(q string) string {
	return strings.Join(strings.Fields(q), " ")
}

func (d *fakeDriver) Open(name string) (driver.Conn, error) {
	return &fakeConn{d: d}, nil
}

type fakeConn struct{ d *fakeDriver }

func (c *fakeConn) Prepare(query string) (driver.Stmt, error) {
	return &fakeStmt{c: c, query: query}, nil
}
func (c *fakeConn) Close() error { return nil }
func (c *fakeConn) Begin() (driver.Tx, error) {
	return nil, fmt.Errorf("fakedriver: transactions unsupported")
}

// Query implements driver.Queryer so database/sql can run QueryContext without a Prepare round
// trip — simpler for this fake than also implementing driver.Stmt's Query path.
func (c *fakeConn) Query(query string, args []driver.Value) (driver.Rows, error) {
	c.d.mu.Lock()
	defer c.d.mu.Unlock()
	key := normalizeQuery(query)
	if c.d.failOn[key] {
		return nil, fmt.Errorf("fakedriver: forced failure for query %q", query)
	}
	res, ok := c.d.responses[key]
	if !ok {
		return nil, fmt.Errorf("fakedriver: no response configured for query %q", query)
	}
	return &fakeRows{cols: res.cols, rows: res.rows}, nil
}

type fakeStmt struct {
	c     *fakeConn
	query string
}

func (s *fakeStmt) Close() error  { return nil }
func (s *fakeStmt) NumInput() int { return -1 }
func (s *fakeStmt) Exec(args []driver.Value) (driver.Result, error) {
	return nil, fmt.Errorf("fakedriver: Exec unsupported")
}
func (s *fakeStmt) Query(args []driver.Value) (driver.Rows, error) {
	return s.c.Query(s.query, args)
}

type fakeRows struct {
	cols []string
	rows [][]driver.Value
	pos  int
}

func (r *fakeRows) Columns() []string { return r.cols }
func (r *fakeRows) Close() error      { return nil }
func (r *fakeRows) Next(dest []driver.Value) error {
	if r.pos >= len(r.rows) {
		return io.EOF
	}
	copy(dest, r.rows[r.pos])
	r.pos++
	return nil
}

var _ driver.Driver = (*fakeDriver)(nil)
var _ driver.Queryer = (*fakeConn)(nil)
