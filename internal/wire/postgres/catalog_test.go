package postgres

import (
	"bufio"
	"bytes"
	"context"
	"encoding/binary"
	"fmt"
	"net"
	"testing"
)

func TestParseCatalogDSN(t *testing.T) {
	cred, err := ParseCatalogDSN("postgres://looker:s3cret@catalog.internal:5433/ignored?sslmode=disable")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if cred.Host != "catalog.internal" || cred.Port != "5433" || cred.User != "looker" || cred.Password != "s3cret" || cred.SSLMode != "disable" {
		t.Fatalf("got %+v", cred)
	}
}

func TestParseCatalogDSN_DefaultPort(t *testing.T) {
	cred, err := ParseCatalogDSN("postgres://looker@catalog.internal/db")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if cred.Port != "5432" {
		t.Fatalf("want default port 5432, got %q", cred.Port)
	}
}

func TestParseCatalogDSN_Empty(t *testing.T) {
	if _, err := ParseCatalogDSN(""); err == nil {
		t.Fatal("expected an error for an empty DSN")
	}
}

func TestParseCatalogDSN_WrongScheme(t *testing.T) {
	if _, err := ParseCatalogDSN("mysql://u:p@host/db"); err == nil {
		t.Fatal("expected an error for a non-postgres scheme")
	}
}

func TestParseCatalogDSN_MissingHost(t *testing.T) {
	if _, err := ParseCatalogDSN("postgres:///db"); err == nil {
		t.Fatal("expected an error for a missing host")
	}
}

// fakeCatalogServer accepts one connection, completes a trust-auth handshake (mirroring
// TestAuthenticateUpstreamTrust's pattern), then answers every pg_class simple Query with a fixed
// relname/relnamespace row, and every pg_attribute query with columnName, until the listener is
// closed. columnName == "" makes the pg_attribute branch return zero rows (an unresolved column),
// matching ResolveColumn's "no matching row -> unresolved, not an error" contract.
func fakeCatalogServer(t *testing.T, relname, schema, columnName string) (addr string, closeFn func()) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go serveFakeCatalogConn(conn, relname, schema, columnName)
		}
	}()
	return ln.Addr().String(), func() { _ = ln.Close() }
}

func serveFakeCatalogConn(conn net.Conn, relname, schema, columnName string) {
	defer conn.Close()
	br := bufio.NewReader(conn)

	// StartupMessage.
	var hdr [8]byte
	if _, err := readFull(br, hdr[:]); err != nil {
		return
	}
	length := binary.BigEndian.Uint32(hdr[0:4])
	body := make([]byte, int(length)-8)
	if _, err := readFull(br, body); err != nil {
		return
	}
	if err := writeAuthOK(conn); err != nil {
		return
	}
	if err := writeMsgRaw(conn, 'Z', []byte{'I'}); err != nil {
		return
	}

	for {
		typ, payload, err := readBackendMessage(br)
		if err != nil {
			return
		}
		if typ != msgQuery {
			continue
		}
		if bytes.Contains(payload, []byte("pg_attribute")) {
			if err := writeAttnameRowDescription(conn); err != nil {
				return
			}
			if columnName != "" {
				if err := writeAttnameDataRow(conn, columnName); err != nil {
					return
				}
			}
			if err := writeMsgRaw(conn, 'Z', []byte{'I'}); err != nil {
				return
			}
			continue
		}
		if err := writeCatalogRowDescription(conn); err != nil {
			return
		}
		if err := writeCatalogDataRow(conn, relname, schema); err != nil {
			return
		}
		if err := writeMsgRaw(conn, 'Z', []byte{'I'}); err != nil {
			return
		}
	}
}

func writeAttnameRowDescription(w net.Conn) error {
	var buf bytes.Buffer
	var u16 [2]byte
	binary.BigEndian.PutUint16(u16[:], 1)
	buf.Write(u16[:])
	buf.WriteString("attname")
	buf.WriteByte(0)
	buf.Write(make([]byte, 18))
	return writeMsgRaw(w, 'T', buf.Bytes())
}

func writeAttnameDataRow(w net.Conn, value string) error {
	var buf bytes.Buffer
	var u16 [2]byte
	binary.BigEndian.PutUint16(u16[:], 1)
	buf.Write(u16[:])
	var u32 [4]byte
	binary.BigEndian.PutUint32(u32[:], uint32(len(value)))
	buf.Write(u32[:])
	buf.WriteString(value)
	return writeMsgRaw(w, 'D', buf.Bytes())
}

func writeAuthOK(w net.Conn) error {
	payload := make([]byte, 4)
	binary.BigEndian.PutUint32(payload, authOK)
	return writeMsgRaw(w, msgAuthentication, payload)
}

func writeMsgRaw(w net.Conn, typ byte, payload []byte) error {
	hdr := make([]byte, 5)
	hdr[0] = typ
	binary.BigEndian.PutUint32(hdr[1:5], uint32(len(payload)+4))
	if _, err := w.Write(hdr); err != nil {
		return err
	}
	_, err := w.Write(payload)
	return err
}

func writeCatalogRowDescription(w net.Conn) error {
	var buf bytes.Buffer
	var u16 [2]byte
	binary.BigEndian.PutUint16(u16[:], 2)
	buf.Write(u16[:])
	for _, name := range []string{"relname", "relnamespace"} {
		buf.WriteString(name)
		buf.WriteByte(0)
		buf.Write(make([]byte, 18))
	}
	return writeMsgRaw(w, 'T', buf.Bytes())
}

func writeCatalogDataRow(w net.Conn, relname, schema string) error {
	var buf bytes.Buffer
	var u16 [2]byte
	binary.BigEndian.PutUint16(u16[:], 2)
	buf.Write(u16[:])
	for _, v := range []string{relname, schema} {
		var u32 [4]byte
		binary.BigEndian.PutUint32(u32[:], uint32(len(v)))
		buf.Write(u32[:])
		buf.WriteString(v)
	}
	return writeMsgRaw(w, 'D', buf.Bytes())
}

func TestCatalogResolver_ResolvesAndCaches(t *testing.T) {
	addr, closeFn := fakeCatalogServer(t, "orders", "shop", "")
	defer closeFn()
	host, port, splitErr := net.SplitHostPort(addr)
	if splitErr != nil {
		t.Fatalf("split addr: %v", splitErr)
	}

	r := NewCatalogResolver(CatalogCredential{Host: host, Port: port, User: "u", Password: "p"})
	schema, table, ok := r.Resolve(context.Background(), "shop", 12345)
	if !ok || schema != "shop" || table != "orders" {
		t.Fatalf("Resolve = %q %q %v", schema, table, ok)
	}

	// Second call should hit the cache — verified indirectly: closing the server doesn't break it.
	closeFn()
	schema2, table2, ok2 := r.Resolve(context.Background(), "shop", 12345)
	if !ok2 || schema2 != "shop" || table2 != "orders" {
		t.Fatalf("cached Resolve = %q %q %v", schema2, table2, ok2)
	}
}

func TestCatalogResolver_TableOIDZeroUnresolved(t *testing.T) {
	r := NewCatalogResolver(CatalogCredential{Host: "127.0.0.1", Port: "1"})
	_, _, ok := r.Resolve(context.Background(), "shop", 0)
	if ok {
		t.Fatal("tableOID 0 (no backing table) must never resolve")
	}
}

func TestCatalogResolver_UnreachableServerUnresolved(t *testing.T) {
	// Port 1 is a privileged port very unlikely to have a listener; dial should fail fast within
	// catalogDialTimeout and Resolve must degrade to unresolved rather than blocking/erroring.
	r := NewCatalogResolver(CatalogCredential{Host: "127.0.0.1", Port: "1"})
	_, _, ok := r.Resolve(context.Background(), "shop", 99)
	if ok {
		t.Fatal("expected an unreachable catalog server to resolve as unresolved, not ok")
	}
}

// TestCatalogResolver_ResolveColumn is the regression test for
// docs/PATH_LABEL_IDENTITY_GAPS_DESIGN.md's Gap A at the CatalogResolver level: a real, unaliased
// column name must be resolvable via pg_attribute, independent of (and cached separately from) the
// pg_class table-name resolution Resolve already provides.
func TestCatalogResolver_ResolveColumn(t *testing.T) {
	addr, closeFn := fakeCatalogServer(t, "orders", "shop", "email")
	defer closeFn()
	host, port, err := net.SplitHostPort(addr)
	if err != nil {
		t.Fatalf("split addr: %v", err)
	}

	r := NewCatalogResolver(CatalogCredential{Host: host, Port: port, User: "u", Password: "p"})
	name, ok := r.ResolveColumn(context.Background(), "shop", 12345, 2)
	if !ok || name != "email" {
		t.Fatalf("ResolveColumn = %q %v, want email true", name, ok)
	}

	// Second call should hit the cache — verified indirectly: closing the server doesn't break it.
	closeFn()
	name2, ok2 := r.ResolveColumn(context.Background(), "shop", 12345, 2)
	if !ok2 || name2 != "email" {
		t.Fatalf("cached ResolveColumn = %q %v, want email true", name2, ok2)
	}
}

func TestCatalogResolver_ResolveColumn_NoMatchingRowUnresolved(t *testing.T) {
	addr, closeFn := fakeCatalogServer(t, "orders", "shop", "") // "" -> pg_attribute returns zero rows
	defer closeFn()
	host, port, err := net.SplitHostPort(addr)
	if err != nil {
		t.Fatalf("split addr: %v", err)
	}

	r := NewCatalogResolver(CatalogCredential{Host: host, Port: port, User: "u", Password: "p"})
	name, ok := r.ResolveColumn(context.Background(), "shop", 12345, 2)
	if ok || name != "" {
		t.Fatalf("expected unresolved for a stale attnum with no matching pg_attribute row, got %q %v", name, ok)
	}
}

func TestCatalogResolver_ResolveColumn_TableOIDZeroUnresolved(t *testing.T) {
	r := NewCatalogResolver(CatalogCredential{Host: "127.0.0.1", Port: "1"})
	if _, ok := r.ResolveColumn(context.Background(), "shop", 0, 1); ok {
		t.Fatal("tableOID 0 (no backing table) must never resolve")
	}
}

func TestCatalogResolver_ResolveColumn_AttnumZeroUnresolved(t *testing.T) {
	r := NewCatalogResolver(CatalogCredential{Host: "127.0.0.1", Port: "1"})
	if _, ok := r.ResolveColumn(context.Background(), "shop", 12345, 0); ok {
		t.Fatal("attnum <= 0 (system column or unparseable) must never resolve")
	}
}

func TestCatalogResolver_ResolveColumn_UnreachableServerUnresolved(t *testing.T) {
	r := NewCatalogResolver(CatalogCredential{Host: "127.0.0.1", Port: "1"})
	if _, ok := r.ResolveColumn(context.Background(), "shop", 99, 1); ok {
		t.Fatal("expected an unreachable catalog server to resolve as unresolved, not ok")
	}
}

func TestPeekStartupDatabase(t *testing.T) {
	msg := startupMessage(map[string]string{"user": "alice", "database": "shop"})
	cr := bufio.NewReader(bytes.NewReader(msg))
	got := peekStartupDatabase(cr)
	if got != "shop" {
		t.Fatalf("got %q, want shop", got)
	}
	// Peek must not consume: the same bytes must still be fully readable afterward.
	rest := make([]byte, len(msg))
	if _, err := readFull(cr, rest); err != nil {
		t.Fatalf("read after peek: %v", err)
	}
	if !bytes.Equal(rest, msg) {
		t.Fatal("peekStartupDatabase consumed bytes it should only have peeked")
	}
}

func TestPeekStartupDatabase_FallsBackToUser(t *testing.T) {
	msg := startupMessage(map[string]string{"user": "alice"})
	cr := bufio.NewReader(bytes.NewReader(msg))
	if got := peekStartupDatabase(cr); got != "alice" {
		t.Fatalf("got %q, want alice (libpq default: database defaults to user)", got)
	}
}

func TestPeekStartupDatabase_MalformedReturnsEmpty(t *testing.T) {
	cr := bufio.NewReader(bytes.NewReader([]byte{1, 2, 3}))
	if got := peekStartupDatabase(cr); got != "" {
		t.Fatalf("got %q, want empty for malformed input", got)
	}
}

// TestCatalogResolver_ConnsBoundedByMaxCatalogDatabases is the regression test for the
// maxCatalogDatabases cap: without it, a long-running agent asked to resolve identity against an
// unbounded number of distinct database names (e.g. a client free to pick an arbitrary database in
// its startup packet) would grow CatalogResolver.conns without limit. Prefilling conns to the cap
// and confirming a never-before-seen database resolves as unresolved (rather than attempting to
// dial and add a 201st entry) proves the cap is enforced before any connection attempt.
func TestCatalogResolver_ConnsBoundedByMaxCatalogDatabases(t *testing.T) {
	r := NewCatalogResolver(CatalogCredential{Host: "127.0.0.1", Port: "1"})
	for i := 0; i < maxCatalogDatabases; i++ {
		r.conns[fmt.Sprintf("db%d", i)] = &catalogConn{}
	}
	_, _, ok := r.Resolve(context.Background(), "brand-new-db", 99)
	if ok {
		t.Fatal("expected an unresolved result once maxCatalogDatabases distinct databases are already tracked")
	}
	if len(r.conns) != maxCatalogDatabases {
		t.Fatalf("expected conns to stay at the cap (%d), got %d", maxCatalogDatabases, len(r.conns))
	}
}

// TestCatalogResolver_CacheBoundedByMaxCatalogCacheEntriesPerDB is the regression test for the
// per-database cache size cap: without it, a client driving lookups for many distinct/invalid
// tableOIDs against one database would grow that database's cache map without limit.
func TestCatalogResolver_CacheBoundedByMaxCatalogCacheEntriesPerDB(t *testing.T) {
	addr, closeFn := fakeCatalogServer(t, "orders", "shop", "")
	defer closeFn()
	host, port, err := net.SplitHostPort(addr)
	if err != nil {
		t.Fatalf("split addr: %v", err)
	}

	r := NewCatalogResolver(CatalogCredential{Host: host, Port: port, User: "u", Password: "p"})
	r.cache["shop"] = make(map[uint32]tableInfo, maxCatalogCacheEntriesPerDB)
	for i := uint32(0); i < maxCatalogCacheEntriesPerDB; i++ {
		r.cache["shop"][i] = tableInfo{schema: "s", table: "t"}
	}

	// tableOID chosen outside the prefilled [0, maxCatalogCacheEntriesPerDB) range so this Resolve
	// call is a genuine cache miss that goes to the fake server, not an accidental hit on a dummy
	// prefilled entry.
	schema, table, ok := r.Resolve(context.Background(), "shop", maxCatalogCacheEntriesPerDB+1)
	if !ok || schema != "shop" || table != "orders" {
		t.Fatalf("Resolve = %q %q %v", schema, table, ok)
	}
	if got := len(r.cache["shop"]); got != 1 {
		t.Fatalf("expected the overflowing cache to be cleared down to the new entry (1), got %d", got)
	}
}

// startupMessage builds a v3 StartupMessage for the given params, in the same shape
// writeStartupMessage builds internally but generalized to arbitrary key/value pairs for tests.
func startupMessage(params map[string]string) []byte {
	var body []byte
	for k, v := range params {
		body = append(body, k...)
		body = append(body, 0)
		body = append(body, v...)
		body = append(body, 0)
	}
	body = append(body, 0)
	out := make([]byte, 8+len(body))
	binary.BigEndian.PutUint32(out[0:4], uint32(8+len(body)))
	binary.BigEndian.PutUint32(out[4:8], startupProtocolV3)
	copy(out[8:], body)
	return out
}
