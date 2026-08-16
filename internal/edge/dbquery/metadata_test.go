package dbquery

import (
	"bufio"
	"context"
	"encoding/binary"
	"net"
	"testing"
)

// fakePGRowDescriptionMulti builds a RowDescription for len(cols) text-typed columns — the
// metadata query selects three columns (schema/name/kind), which fakePGRowDescription (a single
// column) can't describe.
func fakePGRowDescriptionMulti(cols []string) []byte {
	rd := []byte{byte(len(cols) >> 8), byte(len(cols))}
	for _, col := range cols {
		rd = append(rd, []byte(col)...)
		rd = append(rd, 0)
		rd = append(rd, 0, 0, 0, 0)  // table oid
		rd = append(rd, 0, 0)        // attnum
		rd = append(rd, 0, 0, 0, 25) // type oid (25 = text)
		rd = append(rd, 0, 4)        // typlen
		rd = append(rd, 0, 0, 0, 0)  // typmod
		rd = append(rd, 0, 0)        // format code (text)
	}
	return rd
}

// fakePostgresServerCols is fakePostgresServer's multi-column counterpart: every incoming simple
// Query gets back a fixed RowDescription/DataRow set over cols, regardless of query text.
func fakePostgresServerCols(t *testing.T, cols []string, rows [][]string) (addr string) {
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

		var lenb [4]byte
		if !fakePGReadFull(br, lenb[:]) {
			return
		}
		length := binary.BigEndian.Uint32(lenb[:])
		body := make([]byte, int(length)-4)
		if !fakePGReadFull(br, body) {
			return
		}

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
				continue
			}
			if err := fakePGWriteMsg(conn, 'T', fakePGRowDescriptionMulti(cols)); err != nil {
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

// TestDiscoverDatabaseMetadataRejectsUnsupportedDriver exercises DiscoverDatabaseMetadata's
// default branch before any connection is attempted.
func TestDiscoverDatabaseMetadataRejectsUnsupportedDriver(t *testing.T) {
	_, err := DiscoverDatabaseMetadata(context.Background(), "oracle", Target{Host: "h"}, "db")
	if err == nil {
		t.Fatal("expected an error for an unsupported driver")
	}
}

// TestDiscoverDatabaseMetadataDefaultsDatabaseFromTarget confirms an empty database argument
// falls back to target.DatabaseName rather than erroring immediately.
func TestDiscoverDatabaseMetadataDefaultsDatabaseFromTarget(t *testing.T) {
	addr := fakePostgresServerCols(t, []string{"schema_name", "object_name", "kind"}, [][]string{{"public", "users", "r"}})
	objects, err := DiscoverDatabaseMetadata(context.Background(), "postgres", Target{
		Host:         addr,
		User:         "u",
		Password:     "p",
		DatabaseName: "fallback_db",
		SSLMode:      "disable&default_query_exec_mode=simple_protocol",
	}, "")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(objects) != 1 {
		t.Fatalf("expected 1 object, got %#v", objects)
	}
}

func TestDiscoverPostgresMetadataMissingHost(t *testing.T) {
	_, err := DiscoverDatabaseMetadata(context.Background(), "postgres", Target{}, "db")
	if err == nil {
		t.Fatal("expected an error for a postgres target with no host")
	}
}

func TestDiscoverPostgresMetadataHappyPath(t *testing.T) {
	addr := fakePostgresServerCols(t, []string{"schema_name", "object_name", "kind"}, [][]string{
		{"public", "users", "r"},
		{"public", "orders", "r"},
	})
	objects, err := DiscoverDatabaseMetadata(context.Background(), "postgres", Target{
		Host:     addr,
		User:     "u",
		Password: "p",
		SSLMode:  "disable&default_query_exec_mode=simple_protocol",
	}, "db")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(objects) != 2 {
		t.Fatalf("expected 2 objects, got %#v", objects)
	}
	if objects[0].GetObjectName() != "users" || objects[1].GetObjectName() != "orders" {
		t.Fatalf("unexpected object names: %#v", objects)
	}
}

func TestDiscoverMysqlMetadataMissingHost(t *testing.T) {
	_, err := DiscoverDatabaseMetadata(context.Background(), "mysql", Target{}, "db")
	if err == nil {
		t.Fatal("expected an error for a mysql target with no host")
	}
}

// fakeMySQLServerCols is fakeMySQLServer's multi-column counterpart, needed because the metadata
// query selects three columns (TABLE_SCHEMA/TABLE_NAME/kind).
func fakeMySQLServerCols(t *testing.T, cols []string, rows [][]string) (addr string) {
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
			if !write([]byte{byte(len(cols))}) { // column count
				return
			}
			for _, col := range cols {
				if !write(fakeMySQLColumnDef(col)) {
					return
				}
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

func TestDiscoverMysqlMetadataHappyPath(t *testing.T) {
	addr := fakeMySQLServerCols(t, []string{"TABLE_SCHEMA", "TABLE_NAME", "kind"}, [][]string{
		{"appdb", "users", "r"},
		{"appdb", "orders", "r"},
	})
	objects, err := DiscoverDatabaseMetadata(context.Background(), "mysql", Target{
		Host: addr,
		User: "u",
	}, "db")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(objects) != 2 {
		t.Fatalf("expected 2 objects, got %#v", objects)
	}
	if objects[0].GetObjectName() != "users" || objects[1].GetObjectName() != "orders" {
		t.Fatalf("unexpected object names: %#v", objects)
	}
}

func TestDiscoverMongoMetadataMissingHost(t *testing.T) {
	_, err := DiscoverDatabaseMetadata(context.Background(), "mongo", Target{}, "db")
	if err == nil {
		t.Fatal("expected an error for a mongo target with no host")
	}
}

func TestDiscoverMongoMetadataHappyPath(t *testing.T) {
	addr := fakeMongoServer(t, fakeMongoServerOpts{listCollNames: []string{"users", "orders"}})
	objects, err := DiscoverDatabaseMetadata(context.Background(), "mongodb", Target{
		Host: addr,
	}, "db")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(objects) != 2 {
		t.Fatalf("expected 2 objects, got %#v", objects)
	}
	if objects[0].GetObjectName() != "users" || objects[0].GetKind() != "collection" {
		t.Fatalf("unexpected object: %#v", objects[0])
	}
	if objects[1].GetObjectName() != "orders" {
		t.Fatalf("unexpected object: %#v", objects[1])
	}
}
