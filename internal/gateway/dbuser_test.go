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

// TestSnifferViaWriterMySQL exercises the "mysql" branch of feed via the io.Writer path (the
// existing TestSnifferViaWriter only exercises postgres).
func TestSnifferViaWriterMySQL(t *testing.T) {
	s := newLoginUserSniffer("MySQL") // mixed case: newLoginUserSniffer lowercases it
	_, _ = s.Write(mysqlHandshakeResponse41("frank"))
	if s.username() != "frank" || !s.done {
		t.Fatalf("got (%q,%v) want (frank,true)", s.username(), s.done)
	}
}

// TestSnifferGivesUpAtCap proves feed() bails out (done=true, user="") once the buffered bytes hit
// sniffCap without ever producing a parseable handshake, so a pathological stream can't grow memory
// unbounded (see feed's "give up rather than buffer unbounded" comment).
func TestSnifferGivesUpAtCap(t *testing.T) {
	s := newLoginUserSniffer("postgres")
	// Header advertises a StartupMessage of exactly sniffCap bytes (within the "uninteresting"
	// length>sniffCap guard), but we never actually deliver that many bytes — sniffPostgresUser keeps
	// returning done=false ("wait for the full StartupMessage") until feed's own cap check kicks in
	// once the buffered total reaches sniffCap.
	header := make([]byte, 8)
	binary.BigEndian.PutUint32(header[0:4], sniffCap)
	binary.BigEndian.PutUint32(header[4:8], 196608) // ordinary protocol version, not a special code
	_, _ = s.Write(header)
	if s.done {
		t.Fatalf("expected sniffer to still be waiting for more bytes after just the header")
	}
	chunk := make([]byte, 4096)
	for i := 0; i < 5 && !s.done; i++ {
		_, _ = s.Write(chunk)
	}
	if !s.done {
		t.Fatalf("expected sniffer to give up once sniffCap is reached")
	}
	if s.username() != "" {
		t.Fatalf("expected no username, got %q", s.username())
	}
}

func TestSniffPostgresUserCancelRequest(t *testing.T) {
	b := make([]byte, 16)
	binary.BigEndian.PutUint32(b[0:4], 16)
	binary.BigEndian.PutUint32(b[4:8], pgCancelRequestCode)
	user, done := sniffPostgresUser(b)
	if !done || user != "" {
		t.Fatalf("got (%q,%v) want (\"\",true) for CancelRequest", user, done)
	}
}

func TestSniffPostgresUserMalformedLength(t *testing.T) {
	b := make([]byte, 8)
	binary.BigEndian.PutUint32(b[0:4], 3) // length < 8: malformed
	binary.BigEndian.PutUint32(b[4:8], 999)
	user, done := sniffPostgresUser(b)
	if !done || user != "" {
		t.Fatalf("got (%q,%v) want (\"\",true) for malformed length", user, done)
	}
}

func TestSniffPostgresUserOversizedLength(t *testing.T) {
	b := make([]byte, 8)
	binary.BigEndian.PutUint32(b[0:4], sniffCap+1) // length > sniffCap: uninteresting
	binary.BigEndian.PutUint32(b[4:8], 12345)
	user, done := sniffPostgresUser(b)
	if !done || user != "" {
		t.Fatalf("got (%q,%v) want (\"\",true) for oversized length", user, done)
	}
}

func TestSniffPostgresUserWaitsForFullStartupMessage(t *testing.T) {
	full := pgStartup("user", "grace", "database", "prod")
	// Trim to more than 8 bytes (past header classification) but short of the full frame, so
	// sniffPostgresUser hits the "wait for the full StartupMessage" branch (len(buf)-off < length).
	partial := full[:len(full)-3]
	user, done := sniffPostgresUser(partial)
	if done || user != "" {
		t.Fatalf("partial startup past the header should ask for more bytes, got (%q,%v)", user, done)
	}
}

func TestPgUserFromParamsNoUserKey(t *testing.T) {
	if got := pgUserFromParams([]byte("database\x00prod\x00")); got != "" {
		t.Fatalf("got %q want empty when no user key present", got)
	}
}

func TestSniffMySQLUserNeedsMoreHeaderBytes(t *testing.T) {
	user, done := sniffMySQLUser([]byte{1, 2})
	if done || user != "" {
		t.Fatalf("got (%q,%v) want (\"\",false) with fewer than 4 header bytes", user, done)
	}
}

func TestSniffMySQLUserTooSmallForHandshake(t *testing.T) {
	pkt := []byte{10, 0, 0, 1} // 3-byte length=10 < 33 minimum, seq=1
	user, done := sniffMySQLUser(pkt)
	if !done || user != "" {
		t.Fatalf("got (%q,%v) want (\"\",true) for undersized handshake", user, done)
	}
}

func TestSniffMySQLUserWaitsForFullPacket(t *testing.T) {
	full := mysqlHandshakeResponse41("henry")
	partial := full[:len(full)-2] // header advertises the full length but body is short
	user, done := sniffMySQLUser(partial)
	if done || user != "" {
		t.Fatalf("got (%q,%v) want (\"\",false) when payload bytes are still missing", user, done)
	}
}

func TestSniffMySQLUserPre41Capability(t *testing.T) {
	payload := make([]byte, 40)
	// caps left at 0: CLIENT_PROTOCOL_41 bit unset.
	pkt := make([]byte, 4+len(payload))
	pkt[0] = byte(len(payload))
	pkt[1] = byte(len(payload) >> 8)
	pkt[2] = byte(len(payload) >> 16)
	pkt[3] = 1
	copy(pkt[4:], payload)
	user, done := sniffMySQLUser(pkt)
	if !done || user != "" {
		t.Fatalf("got (%q,%v) want (\"\",true) for pre-4.1 capability flags", user, done)
	}
}

func TestSniffMySQLUserNoNullTerminator(t *testing.T) {
	payload := make([]byte, 32)
	binary.LittleEndian.PutUint32(payload[0:4], mysqlClientProtocol41)
	payload = append(payload, []byte("noterm")...) // no trailing 0x00
	pkt := make([]byte, 4+len(payload))
	pkt[0] = byte(len(payload))
	pkt[1] = byte(len(payload) >> 8)
	pkt[2] = byte(len(payload) >> 16)
	pkt[3] = 1
	copy(pkt[4:], payload)
	user, done := sniffMySQLUser(pkt)
	if !done || user != "" {
		t.Fatalf("got (%q,%v) want (\"\",true) when the username is never null-terminated", user, done)
	}
}
