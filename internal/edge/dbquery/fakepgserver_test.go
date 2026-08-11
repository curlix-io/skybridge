package dbquery

import (
	"bufio"
	"context"
	"encoding/binary"
	"net"
	"testing"
)

// fakePGReadFull reads exactly len(buf) bytes or returns on error (best-effort — the fake server
// loop only needs to keep reading until the client disconnects).
func fakePGReadFull(r *bufio.Reader, buf []byte) bool {
	n := 0
	for n < len(buf) {
		k, err := r.Read(buf[n:])
		if err != nil {
			return false
		}
		n += k
	}
	return true
}

func fakePGWriteMsg(w net.Conn, typ byte, payload []byte) error {
	hdr := make([]byte, 5)
	hdr[0] = typ
	binary.BigEndian.PutUint32(hdr[1:5], uint32(len(payload)+4))
	if _, err := w.Write(hdr); err != nil {
		return err
	}
	_, err := w.Write(payload)
	return err
}

func fakePGParamStatus(name, value string) []byte {
	b := append([]byte(name), 0)
	b = append(b, append([]byte(value), 0)...)
	return b
}

// fakePGRowDescription builds a minimal RowDescription for a single text-typed column named col.
func fakePGRowDescription(col string) []byte {
	rd := []byte{0, 1}
	rd = append(rd, []byte(col)...)
	rd = append(rd, 0)
	rd = append(rd, 0, 0, 0, 0)  // table oid
	rd = append(rd, 0, 0)        // attnum
	rd = append(rd, 0, 0, 0, 25) // type oid (25 = text, so pgx scans it as a string, not int4)
	rd = append(rd, 0, 4)        // typlen
	rd = append(rd, 0, 0, 0, 0)  // typmod
	rd = append(rd, 0, 0)        // format code (text)
	return rd
}

func fakePGDataRow(vals ...string) []byte {
	d := []byte{byte(len(vals) >> 8), byte(len(vals))}
	for _, v := range vals {
		l := len(v)
		d = append(d, byte(l>>24), byte(l>>16), byte(l>>8), byte(l))
		d = append(d, v...)
	}
	return d
}

// fakePostgresServer speaks just enough of the v3 startup + simple-query protocol (no SSL, no
// extended protocol) to let database/sql's QueryContext (via pgx's default_query_exec_mode
// falling back to simple protocol on 0-argument queries) complete successfully. This is entirely
// in-process/hermetic — no real Postgres server, per CLAUDE.md's testing guidance.
//
// rowsFn is called once per incoming simple Query message and returns the column name plus the
// row values to reply with.
func fakePostgresServer(t *testing.T, col string, rows [][]string) (addr string) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	go func() {
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		defer conn.Close()
		br := bufio.NewReader(conn)

		// StartupMessage.
		var lenb [4]byte
		if !fakePGReadFull(br, lenb[:]) {
			return
		}
		length := binary.BigEndian.Uint32(lenb[:])
		body := make([]byte, int(length)-4)
		if !fakePGReadFull(br, body) {
			return
		}

		// AuthenticationOK + the parameter statuses pgx's simple-protocol path requires.
		if fakePGWriteMsg(conn, 'R', []byte{0, 0, 0, 0}) != nil {
			return
		}
		_ = fakePGWriteMsg(conn, 'S', fakePGParamStatus("standard_conforming_strings", "on"))
		_ = fakePGWriteMsg(conn, 'S', fakePGParamStatus("server_version", "14.0"))
		_ = fakePGWriteMsg(conn, 'S', fakePGParamStatus("client_encoding", "UTF8"))
		if fakePGWriteMsg(conn, 'Z', []byte{'I'}) != nil {
			return
		}

		for {
			typ, err := br.ReadByte()
			if err != nil {
				return
			}
			var mlen [4]byte
			if !fakePGReadFull(br, mlen[:]) {
				return
			}
			l := binary.BigEndian.Uint32(mlen[:])
			payload := make([]byte, int(l)-4)
			if !fakePGReadFull(br, payload) {
				return
			}
			if typ != 'Q' {
				continue // ignore anything that isn't a simple Query (e.g. Terminate handled by read error)
			}
			if err := fakePGWriteMsg(conn, 'T', fakePGRowDescription(col)); err != nil {
				return
			}
			for _, row := range rows {
				if err := fakePGWriteMsg(conn, 'D', fakePGDataRow(row...)); err != nil {
					return
				}
			}
			cmdTag := append([]byte("SELECT "), []byte(itoaFakePG(len(rows)))...)
			cmdTag = append(cmdTag, 0)
			if err := fakePGWriteMsg(conn, 'C', cmdTag); err != nil {
				return
			}
			if err := fakePGWriteMsg(conn, 'Z', []byte{'I'}); err != nil {
				return
			}
		}
	}()
	return ln.Addr().String()
}

func itoaFakePG(n int) string {
	if n == 0 {
		return "0"
	}
	digits := []byte{}
	for n > 0 {
		digits = append([]byte{byte('0' + n%10)}, digits...)
		n /= 10
	}
	return string(digits)
}

// TestExecutePostgresHappyPathMasksRows exercises executePostgres's full success path (dial via
// the fake server above, column/row scan, capRows, maskRows) — the only branch every prior
// postgres test (cancelled-context dials, missing-host guards) never reached.
func TestExecutePostgresHappyPathMasksRows(t *testing.T) {
	addr := fakePostgresServer(t, "note", [][]string{{"hello"}, {"world"}})
	spy := &pathSpyMasker{}
	res, err := Execute(context.Background(), Target{Host: addr, User: "u", Password: "p", SSLMode: "disable&default_query_exec_mode=simple_protocol"}, "postgres", "db", "SELECT note FROM t", Options{
		Masker:   spy,
		ApplyPII: true,
		OrgID:    "org1",
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	results, ok := res["results"].(map[string]any)
	if !ok {
		t.Fatalf("expected results map, got %#v", res)
	}
	data, ok := results["data"].([]map[string]any)
	if !ok || len(data) != 2 {
		t.Fatalf("expected 2 rows, got %#v", results["data"])
	}
	if data[0]["note"] != "hello" || data[1]["note"] != "world" {
		t.Fatalf("unexpected row values: %#v", data)
	}
	if len(spy.seen) != 2 {
		t.Fatalf("expected maskRows to see 2 columns (one per row), got %d", len(spy.seen))
	}
	for _, c := range spy.seen {
		if c.ObjectID == "" {
			t.Fatalf("expected ObjectID populated when OrgID is set, got %+v", c)
		}
	}
}

// TestExecutePostgresHappyPathCapsRows exercises capRows' truncation branch on a live (fake)
// result set, and confirms MaxRows actually limits what's masked/returned.
func TestExecutePostgresHappyPathCapsRows(t *testing.T) {
	addr := fakePostgresServer(t, "n", [][]string{{"1"}, {"2"}, {"3"}})
	res, err := Execute(context.Background(), Target{Host: addr, User: "u", Password: "p", SSLMode: "disable&default_query_exec_mode=simple_protocol"}, "postgres", "db", "SELECT n FROM t", Options{MaxRows: 2})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	results := res["results"].(map[string]any)
	data := results["data"].([]map[string]any)
	if len(data) != 2 {
		t.Fatalf("expected capRows to truncate to 2 rows, got %d", len(data))
	}
}

// TestExecutePostgresHappyPathNoMasker confirms the nil-masker (ApplyPII=false) path returns rows
// verbatim through the same live-dial code path.
func TestExecutePostgresHappyPathNoMasker(t *testing.T) {
	addr := fakePostgresServer(t, "note", [][]string{{"raw-value"}})
	res, err := Execute(context.Background(), Target{Host: addr, User: "u", Password: "p", SSLMode: "disable&default_query_exec_mode=simple_protocol"}, "postgres", "db", "SELECT note FROM t", Options{ApplyPII: false, Masker: &pathSpyMasker{}})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	results := res["results"].(map[string]any)
	data := results["data"].([]map[string]any)
	if data[0]["note"] != "raw-value" {
		t.Fatalf("expected verbatim value with masking disabled, got %v", data[0]["note"])
	}
}

// TestExecuteWriteSQLPostgresHappyPath exercises executeWriteSQL's postgres success branch
// (ExecContext, RowsAffected) against the fake server, using a lightweight CommandComplete-only
// reply path (no RowDescription/DataRow needed for a write).
func TestExecuteWriteSQLPostgresHappyPath(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	go func() {
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		defer conn.Close()
		br := bufio.NewReader(conn)
		var lenb [4]byte
		if !fakePGReadFull(br, lenb[:]) {
			return
		}
		length := binary.BigEndian.Uint32(lenb[:])
		body := make([]byte, int(length)-4)
		if !fakePGReadFull(br, body) {
			return
		}
		_ = fakePGWriteMsg(conn, 'R', []byte{0, 0, 0, 0})
		_ = fakePGWriteMsg(conn, 'S', fakePGParamStatus("standard_conforming_strings", "on"))
		_ = fakePGWriteMsg(conn, 'S', fakePGParamStatus("server_version", "14.0"))
		_ = fakePGWriteMsg(conn, 'S', fakePGParamStatus("client_encoding", "UTF8"))
		if fakePGWriteMsg(conn, 'Z', []byte{'I'}) != nil {
			return
		}
		for {
			typ, err := br.ReadByte()
			if err != nil {
				return
			}
			var mlen [4]byte
			if !fakePGReadFull(br, mlen[:]) {
				return
			}
			l := binary.BigEndian.Uint32(mlen[:])
			payload := make([]byte, int(l)-4)
			if !fakePGReadFull(br, payload) {
				return
			}
			if typ != 'Q' {
				continue
			}
			cmdTag := append([]byte("UPDATE 1"), 0)
			if err := fakePGWriteMsg(conn, 'C', cmdTag); err != nil {
				return
			}
			if err := fakePGWriteMsg(conn, 'Z', []byte{'I'}); err != nil {
				return
			}
		}
	}()
	res, err := Execute(context.Background(), Target{Host: ln.Addr().String(), User: "u", Password: "p", SSLMode: "disable&default_query_exec_mode=simple_protocol"}, "postgres", "db", "UPDATE t SET x=1", Options{Write: true})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	results, ok := res["results"].(map[string]any)
	if !ok {
		t.Fatalf("expected results map, got %#v", res)
	}
	if _, ok := results["rows_affected"]; !ok {
		t.Fatalf("expected rows_affected in results, got %#v", results)
	}
}
