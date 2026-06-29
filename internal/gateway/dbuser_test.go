package gateway

import (
	"encoding/binary"
	"testing"
)

// pgStartup builds a Postgres StartupMessage carrying the given key/value params.
func pgStartup(params ...string) []byte {
	body := make([]byte, 4) // protocol version 3.0
	binary.BigEndian.PutUint32(body, 196608)
	for _, p := range params {
		body = append(body, []byte(p)...)
		body = append(body, 0)
	}
	body = append(body, 0) // terminator
	out := make([]byte, 4+len(body))
	binary.BigEndian.PutUint32(out, uint32(4+len(body)))
	copy(out[4:], body)
	return out
}

func pgSSLRequest() []byte {
	b := make([]byte, 8)
	binary.BigEndian.PutUint32(b[0:4], 8)
	binary.BigEndian.PutUint32(b[4:8], pgSSLRequestCode)
	return b
}

// mysqlHandshakeResponse41 builds a minimal HandshakeResponse41 packet with the given username.
func mysqlHandshakeResponse41(user string) []byte {
	payload := make([]byte, 32)
	binary.LittleEndian.PutUint32(payload[0:4], mysqlClientProtocol41)
	payload = append(payload, []byte(user)...)
	payload = append(payload, 0)
	pkt := make([]byte, 4+len(payload))
	pkt[0] = byte(len(payload))
	pkt[1] = byte(len(payload) >> 8)
	pkt[2] = byte(len(payload) >> 16)
	pkt[3] = 1 // sequence id
	copy(pkt[4:], payload)
	return pkt
}

func TestSniffPostgresUser(t *testing.T) {
	user, done := sniffPostgresUser(pgStartup("user", "alice", "database", "prod"))
	if !done || user != "alice" {
		t.Fatalf("got (%q,%v) want (alice,true)", user, done)
	}
}

func TestSniffPostgresUserSkipsSSLRequest(t *testing.T) {
	buf := append(pgSSLRequest(), pgStartup("user", "bob", "database", "x")...)
	user, done := sniffPostgresUser(buf)
	if !done || user != "bob" {
		t.Fatalf("got (%q,%v) want (bob,true)", user, done)
	}
}

func TestSniffPostgresUserNeedsMoreBytes(t *testing.T) {
	full := pgStartup("user", "carol")
	if user, done := sniffPostgresUser(full[:6]); done || user != "" {
		t.Fatalf("partial startup should ask for more bytes, got (%q,%v)", user, done)
	}
}

func TestSniffMySQLUser(t *testing.T) {
	user, done := sniffMySQLUser(mysqlHandshakeResponse41("dave"))
	if !done || user != "dave" {
		t.Fatalf("got (%q,%v) want (dave,true)", user, done)
	}
}

func TestSnifferViaWriter(t *testing.T) {
	s := newLoginUserSniffer("postgres")
	startup := pgStartup("user", "erin", "database", "y")
	// Feed in two chunks to exercise incremental accumulation.
	_, _ = s.Write(startup[:5])
	if s.username() != "" {
		t.Fatalf("username known too early: %q", s.username())
	}
	_, _ = s.Write(startup[5:])
	_, _ = s.Write([]byte("SELECT 1")) // post-handshake traffic is ignored
	if s.username() != "erin" {
		t.Fatalf("username = %q want erin", s.username())
	}
}

func TestSnifferUnknownProtocol(t *testing.T) {
	s := newLoginUserSniffer("mongodb")
	_, _ = s.Write([]byte("anything"))
	if s.username() != "" || !s.done {
		t.Fatalf("mongo should yield no username and be done, got (%q, done=%v)", s.username(), s.done)
	}
}
