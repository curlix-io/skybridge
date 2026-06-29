package gateway

import (
	"encoding/binary"
	"io"
	"strings"
)

// Per-connection actor attribution: the database login username uniquely identifies a credential
// lease (vault_dynamic / session_user mint a fresh, globally-unique username per grant), so reporting
// it lets the control plane attribute a relayed session to its owner even when several users share
// one resource role. The gateway relays the client->upstream direction unmasked (only result rows are
// masked, on the agent), so the auth handshake is observable here without any DB driver.
//
// This is deliberately a minimal, read-only metadata sniff — not a wire engine. It parses only the
// one field it needs from the first auth packet and is fully best-effort: any protocol it cannot
// parse, or a partial / non-standard handshake, simply yields "" and the session stays attributed by
// resource role (or honestly unattributed).

const (
	pgSSLRequestCode    = 80877103
	pgGSSRequestCode    = 80877104
	pgCancelRequestCode = 80877102

	mysqlClientProtocol41 = 0x00000200 // CLIENT_PROTOCOL_41 capability flag

	// sniffCap bounds how many leading client bytes we buffer while looking for the username, so a
	// stream that never produces a parseable handshake cannot grow memory unbounded.
	sniffCap = 16 << 10
)

// loginUserSniffer extracts the DB login username from the client->upstream byte stream of a relayed
// native session. It implements io.Writer so it can sit in an io.TeeReader on the up-direction copy;
// once it has an answer (or gives up) further writes are cheap no-ops and never affect the relay.
type loginUserSniffer struct {
	dbType string
	buf    []byte
	done   bool
	user   string
}

func newLoginUserSniffer(dbType string) *loginUserSniffer {
	return &loginUserSniffer{dbType: strings.ToLower(strings.TrimSpace(dbType))}
}

// Write implements io.Writer. It never errors and never blocks, so a tap on the relay is transparent.
func (s *loginUserSniffer) Write(p []byte) (int, error) {
	if !s.done {
		s.feed(p)
	}
	return len(p), nil
}

func (s *loginUserSniffer) feed(p []byte) {
	s.buf = append(s.buf, p...)
	switch s.dbType {
	case "postgres", "postgresql":
		s.user, s.done = sniffPostgresUser(s.buf)
	case "mysql":
		s.user, s.done = sniffMySQLUser(s.buf)
	default:
		s.done = true // Mongo / unknown: no cheap username in the first packet — leave unattributed here.
	}
	if !s.done && len(s.buf) >= sniffCap {
		s.done = true // give up rather than buffer unbounded
	}
}

// username returns the sniffed login (possibly "").
func (s *loginUserSniffer) username() string { return s.user }

// sniffPostgresUser parses the StartupMessage's "user" parameter, skipping any leading
// SSLRequest/GSSENCRequest frames the client sends before it. Returns (user, done): done=false means
// "need more bytes"; done=true with user="" means "nothing to find here".
func sniffPostgresUser(buf []byte) (string, bool) {
	off := 0
	for {
		if len(buf)-off < 8 {
			return "", false // need length+code to classify the frame
		}
		length := int(binary.BigEndian.Uint32(buf[off : off+4]))
		code := binary.BigEndian.Uint32(buf[off+4 : off+8])
		if length == 8 && (code == pgSSLRequestCode || code == pgGSSRequestCode) {
			off += 8 // negotiation frame (the agent answers it); skip and look at the next one
			continue
		}
		if code == pgCancelRequestCode {
			return "", true // CancelRequest, not an auth handshake
		}
		if length < 8 || length > sniffCap {
			return "", true // malformed / uninteresting
		}
		if len(buf)-off < length {
			return "", false // wait for the full StartupMessage
		}
		// StartupMessage: Int32 length, Int32 protocol version, then "key\0value\0...\0".
		return pgUserFromParams(buf[off+8 : off+length]), true
	}
}

func pgUserFromParams(params []byte) string {
	parts := splitCStrings(params)
	for i := 0; i+1 < len(parts); i += 2 {
		if parts[i] == "user" {
			return parts[i+1]
		}
	}
	return ""
}

// sniffMySQLUser parses the username from a HandshakeResponse41 packet (the client's first packet,
// sent after the server greeting). Returns (user, done) with the same convention as the PG sniffer.
func sniffMySQLUser(buf []byte) (string, bool) {
	if len(buf) < 4 {
		return "", false
	}
	plen := int(buf[0]) | int(buf[1])<<8 | int(buf[2])<<16 // 3-byte little-endian payload length
	if plen < 33 {
		return "", true // too small to be a 4.1 handshake response with a username
	}
	if len(buf) < 4+plen {
		return "", false // wait for the full packet (header is 4 bytes: 3 length + 1 seq)
	}
	payload := buf[4 : 4+plen]
	if len(payload) < 32 {
		return "", true
	}
	caps := binary.LittleEndian.Uint32(payload[0:4])
	if caps&mysqlClientProtocol41 == 0 {
		return "", true // pre-4.1 handshake layout differs; not parsed
	}
	// capabilities(4) max_packet(4) charset(1) filler(23) = 32 bytes, then null-terminated username.
	name := payload[32:]
	if end := indexZeroByte(name); end >= 0 {
		return string(name[:end]), true
	}
	return "", true
}

// splitCStrings splits a buffer of null-terminated strings, dropping the trailing empty terminator.
func splitCStrings(p []byte) []string {
	var out []string
	start := 0
	for i := 0; i < len(p); i++ {
		if p[i] == 0 {
			out = append(out, string(p[start:i]))
			start = i + 1
		}
	}
	return out
}

func indexZeroByte(p []byte) int {
	for i := 0; i < len(p); i++ {
		if p[i] == 0 {
			return i
		}
	}
	return -1
}

// tapReader wraps r so every byte read is also written to tap (best-effort). Used to sniff the login
// username off the live relay without consuming or delaying any bytes.
func tapReader(r io.Reader, tap io.Writer) io.Reader {
	if tap == nil {
		return r
	}
	return io.TeeReader(r, tap)
}
