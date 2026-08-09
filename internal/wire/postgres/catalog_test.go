package postgres

import (
	"bufio"
	"bytes"
	"context"
	"encoding/binary"
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
// TestAuthenticateUpstreamTrust's pattern), then answers every simple Query with a fixed
// relname/relnamespace row until the listener is closed.
func fakeCatalogServer(t *testing.T, relname, schema string) (addr string, closeFn func()) {
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
			go serveFakeCatalogConn(conn, relname, schema)
		}
	}()
	return ln.Addr().String(), func() { _ = ln.Close() }
}

func serveFakeCatalogConn(conn net.Conn, relname, schema string) {
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
		_ = payload
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
	addr, closeFn := fakeCatalogServer(t, "orders", "shop")
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
