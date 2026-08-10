//go:build querystudio

package dbquery

import (
	"bufio"
	"context"
	"net"
	"testing"
)

func fakeMySQLPacket(seq byte, payload []byte) []byte {
	hdr := make([]byte, 4)
	l := len(payload)
	hdr[0] = byte(l)
	hdr[1] = byte(l >> 8)
	hdr[2] = byte(l >> 16)
	hdr[3] = seq
	return append(hdr, payload...)
}

func fakeMySQLReadPacket(br *bufio.Reader) (seq byte, payload []byte, ok bool) {
	hdr := make([]byte, 4)
	if !fakePGReadFull(br, hdr) {
		return 0, nil, false
	}
	l := int(hdr[0]) | int(hdr[1])<<8 | int(hdr[2])<<16
	payload = make([]byte, l)
	if !fakePGReadFull(br, payload) {
		return 0, nil, false
	}
	return hdr[3], payload, true
}

// fakeMySQLGreeting builds a v10 Initial Handshake advertising mysql_native_password with an
// (unused, since the fake server never validates the client's scramble) 20-byte nonce.
func fakeMySQLGreeting() []byte {
	nonce := []byte("01234567890123456789")
	g := []byte{0x0a}
	g = append(g, "8.0.0-test"...)
	g = append(g, 0)
	g = append(g, 9, 0, 0, 0)
	g = append(g, nonce[:8]...)
	g = append(g, 0)
	capLower := uint16(0x0200 | 0x8000) // CLIENT_PROTOCOL_41 | CLIENT_SECURE_CONNECTION
	g = append(g, byte(capLower), byte(capLower>>8))
	g = append(g, 0x21)
	g = append(g, 0x02, 0x00)
	capUpper := uint16(0x0008) // CLIENT_PLUGIN_AUTH >> 16
	g = append(g, byte(capUpper), byte(capUpper>>8))
	g = append(g, byte(len(nonce)+1))
	g = append(g, make([]byte, 10)...)
	g = append(g, nonce[8:20]...)
	g = append(g, 0)
	g = append(g, "mysql_native_password"...)
	g = append(g, 0)
	return g
}

// fakeMySQLColumnDef builds a minimal 4.1-protocol column-definition packet for a single named
// text (VARCHAR, type 0xfd) column.
func fakeMySQLColumnDef(name string) []byte {
	col := []byte{0x03, 'd', 'e', 'f'} // catalog
	col = append(col, 0)               // schema
	col = append(col, 0)               // table
	col = append(col, 0)               // org_table
	col = append(col, byte(len(name)))
	col = append(col, name...)
	col = append(col, 0) // org_name
	col = append(col, 0x0c)
	col = append(col, 0x21, 0x00)             // charset
	col = append(col, 0xff, 0xff, 0xff, 0xff) // column length
	col = append(col, 0xfd)                   // type = VARCHAR
	col = append(col, 0x00, 0x00)             // flags
	col = append(col, 0x00)                   // decimals
	col = append(col, 0x00, 0x00)             // filler
	return col
}

func fakeMySQLTextRow(vals ...string) []byte {
	row := []byte{}
	for _, v := range vals {
		row = append(row, byte(len(v)))
		row = append(row, v...)
	}
	return row
}

// fakeMySQLServer speaks just enough of the classic (non-deprecate-EOF) text protocol — Initial
// Handshake, an unconditional OK to any HandshakeResponse (auth is never actually verified, since
// this package's executors don't test the wire proxy's own auth path), and a fixed COM_QUERY
// reply — to exercise executeMySQL's success path hermetically, without a live MySQL server.
func fakeMySQLServer(t *testing.T, col string, rows [][]string) (addr string) {
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

		if _, err := conn.Write(fakeMySQLPacket(0, fakeMySQLGreeting())); err != nil {
			return
		}
		if _, _, ok := fakeMySQLReadPacket(br); !ok {
			return
		}
		// Unconditional OK (no CLIENT_DEPRECATE_EOF from us to worry about at handshake time).
		ok := []byte{0x00, 0x00, 0x00, 0x02, 0x00, 0x00, 0x00}
		if _, err := conn.Write(fakeMySQLPacket(2, ok)); err != nil {
			return
		}

		for {
			_, payload, readOK := fakeMySQLReadPacket(br)
			if !readOK || len(payload) == 0 {
				return
			}
			if payload[0] != 0x03 { // COM_QUERY
				continue
			}
			seq := byte(1)
			write := func(p []byte) bool {
				if _, err := conn.Write(fakeMySQLPacket(seq, p)); err != nil {
					return false
				}
				seq++
				return true
			}
			if !write([]byte{0x01}) { // column count
				return
			}
			if !write(fakeMySQLColumnDef(col)) {
				return
			}
			if !write([]byte{0xfe, 0x00, 0x00, 0x02, 0x00}) { // EOF after column defs
				return
			}
			for _, row := range rows {
				if !write(fakeMySQLTextRow(row...)) {
					return
				}
			}
			if !write([]byte{0xfe, 0x00, 0x00, 0x02, 0x00}) { // final EOF
				return
			}
		}
	}()
	return ln.Addr().String()
}

// TestExecuteMySQLHappyPathMasksRows exercises executeMySQL's full success path (dial, column
// scan, row scan, capRows, maskRows) against fakeMySQLServer — the branch none of the
// cancelled-context/missing-host tests in executor2_test.go reach.
func TestExecuteMySQLHappyPathMasksRows(t *testing.T) {
	addr := fakeMySQLServer(t, "note", [][]string{{"alpha"}, {"beta"}})
	spy := &pathSpyMasker{}
	res, err := Execute(context.Background(), Target{Host: addr, User: "u"}, "mysql", "db", "SELECT note FROM t", Options{
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
	if data[0]["note"] != "alpha" || data[1]["note"] != "beta" {
		t.Fatalf("unexpected row values: %#v", data)
	}
	if len(spy.seen) != 2 {
		t.Fatalf("expected maskRows to see 2 columns, got %d", len(spy.seen))
	}
}

// TestExecuteMySQLHappyPathCapsRows exercises capRows' truncation branch against a live (fake)
// MySQL result set.
func TestExecuteMySQLHappyPathCapsRows(t *testing.T) {
	addr := fakeMySQLServer(t, "n", [][]string{{"1"}, {"2"}, {"3"}})
	res, err := Execute(context.Background(), Target{Host: addr, User: "u"}, "mysql", "db", "SELECT n FROM t", Options{MaxRows: 2})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	results := res["results"].(map[string]any)
	data := results["data"].([]map[string]any)
	if len(data) != 2 {
		t.Fatalf("expected capRows to truncate to 2 rows, got %d", len(data))
	}
}

// fakeMySQLWriteServer replies to any COM_QUERY with an OK packet reporting affectedRows —
// exercises executeWriteSQL's mysql branch (ExecContext -> RowsAffected) hermetically.
func fakeMySQLWriteServer(t *testing.T, affectedRows byte) (addr string) {
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
		if _, err := conn.Write(fakeMySQLPacket(0, fakeMySQLGreeting())); err != nil {
			return
		}
		if _, _, ok := fakeMySQLReadPacket(br); !ok {
			return
		}
		okPkt := []byte{0x00, 0x00, 0x00, 0x02, 0x00, 0x00, 0x00}
		if _, err := conn.Write(fakeMySQLPacket(2, okPkt)); err != nil {
			return
		}
		for {
			_, payload, readOK := fakeMySQLReadPacket(br)
			if !readOK || len(payload) == 0 {
				return
			}
			if payload[0] != 0x03 {
				continue
			}
			resp := []byte{0x00, affectedRows, 0x00, 0x02, 0x00, 0x00, 0x00}
			if _, err := conn.Write(fakeMySQLPacket(1, resp)); err != nil {
				return
			}
		}
	}()
	return ln.Addr().String()
}

// TestExecuteWriteSQLMySQLHappyPath exercises executeWriteSQL's mysql branch (DSN build without
// pgx aliasing, ExecContext, RowsAffected) against fakeMySQLWriteServer.
func TestExecuteWriteSQLMySQLHappyPath(t *testing.T) {
	addr := fakeMySQLWriteServer(t, 3)
	res, err := Execute(context.Background(), Target{Host: addr, User: "u"}, "mysql", "db", "UPDATE t SET x=1", Options{Write: true})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	results, ok := res["results"].(map[string]any)
	if !ok {
		t.Fatalf("expected results map, got %#v", res)
	}
	affected, ok := results["rows_affected"].(int64)
	if !ok || affected != 3 {
		t.Fatalf("expected rows_affected=3, got %#v", results["rows_affected"])
	}
}
