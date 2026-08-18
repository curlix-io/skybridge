package gateway

import (
	"bufio"
	"errors"
	"fmt"
	"io"
	"net"
	"time"
)

// PeekClientHelloSNI reads (without consuming, from the caller's perspective) enough of a raw TCP
// connection's first bytes to extract the TLS ClientHello's server_name extension, then returns a
// net.Conn that replays those exact bytes before falling through to the real connection — so
// whatever comes after (the gateway's existing byte-blind relay) sees the identical byte stream a
// caller that never peeked would have seen. This is what makes org resolution by SNI compatible
// with the gateway's TLS-blind-relay design (docs/design/kubernetes-access-broker.md §11.1/§11.5):
// only the cleartext ClientHello record is inspected — every byte after it, including the rest of
// the TLS handshake, is relayed completely opaque, same as always.
//
// Returns ("", conn, nil) — not an error — when the connection isn't starting a TLS handshake at
// all, or has no server_name extension: callers should fall back to whatever they'd otherwise do
// (a statically configured org, for example), not drop the connection. A non-nil error means the
// peek itself failed (read timeout, connection closed) — that's the caller's decision on whether to
// abort.
func PeekClientHelloSNI(conn net.Conn, timeout time.Duration) (sni string, replay net.Conn, err error) {
	if timeout > 0 {
		if err := conn.SetReadDeadline(time.Now().Add(timeout)); err != nil {
			return "", conn, err
		}
		defer conn.SetReadDeadline(time.Time{}) //nolint:errcheck // best-effort deadline clear
	}

	br := bufio.NewReaderSize(conn, 16*1024)

	// TLS record header: type(1) version(2) length(2).
	header, err := br.Peek(5)
	if err != nil {
		return "", &replayConn{Conn: conn, buffered: bufferedSoFar(br)}, wrapPeekErr(err)
	}
	const recordTypeHandshake = 0x16
	if header[0] != recordTypeHandshake {
		return "", &replayConn{Conn: conn, buffered: bufferedSoFar(br)}, nil
	}
	recordLen := int(header[3])<<8 | int(header[4])
	if recordLen <= 0 || recordLen > 16*1024-5 {
		return "", &replayConn{Conn: conn, buffered: bufferedSoFar(br)}, nil
	}

	total := 5 + recordLen
	buf, err := br.Peek(total)
	if err != nil {
		return "", &replayConn{Conn: conn, buffered: bufferedSoFar(br)}, wrapPeekErr(err)
	}
	// Copy: Peek's returned slice is only valid until the next read from br, and we're about to
	// hand the *br itself* off wrapped in the replay conn below.
	captured := make([]byte, len(buf))
	copy(captured, buf)

	sni, _ = parseClientHelloSNI(captured[5 : 5+recordLen])
	return sni, &replayConn{Conn: conn, buffered: captured}, nil
}

func wrapPeekErr(err error) error {
	if errors.Is(err, io.EOF) {
		return nil // connection closed before sending anything meaningful — not our error to report
	}
	return fmt.Errorf("peek client hello: %w", err)
}

func bufferedSoFar(br *bufio.Reader) []byte {
	n := br.Buffered()
	if n <= 0 {
		return nil
	}
	buf, _ := br.Peek(n)
	out := make([]byte, len(buf))
	copy(out, buf)
	return out
}

// parseClientHelloSNI extracts the first hostname in the server_name extension (RFC 6066 §3) from
// a raw TLS handshake message (the bytes following the 5-byte record header). Returns ("", false)
// for anything malformed or missing rather than erroring — SNI is optional in TLS, and a parse
// failure here should never be treated as a security-relevant rejection, just "no SNI available."
func parseClientHelloSNI(msg []byte) (string, bool) {
	// Handshake header: msg_type(1) length(3).
	if len(msg) < 4 || msg[0] != 0x01 {
		return "", false
	}
	hsLen := int(msg[1])<<16 | int(msg[2])<<8 | int(msg[3])
	body := msg[4:]
	if len(body) < hsLen {
		return "", false
	}
	body = body[:hsLen]

	// ClientHello: version(2) random(32) session_id_len(1)+session_id.
	if len(body) < 34 {
		return "", false
	}
	pos := 34
	if pos >= len(body) {
		return "", false
	}
	sessionIDLen := int(body[pos])
	pos++
	pos += sessionIDLen
	if pos+2 > len(body) {
		return "", false
	}

	// cipher_suites_len(2) + cipher_suites.
	cipherLen := int(body[pos])<<8 | int(body[pos+1])
	pos += 2 + cipherLen
	if pos+1 > len(body) {
		return "", false
	}

	// compression_methods_len(1) + compression_methods.
	compLen := int(body[pos])
	pos += 1 + compLen
	if pos+2 > len(body) {
		return "", false
	}

	// extensions_len(2) + extensions.
	extLen := int(body[pos])<<8 | int(body[pos+1])
	pos += 2
	if pos+extLen > len(body) {
		return "", false
	}
	extensions := body[pos : pos+extLen]

	const extServerName = 0x0000
	epos := 0
	for epos+4 <= len(extensions) {
		extType := int(extensions[epos])<<8 | int(extensions[epos+1])
		extDataLen := int(extensions[epos+2])<<8 | int(extensions[epos+3])
		epos += 4
		if epos+extDataLen > len(extensions) {
			return "", false
		}
		extData := extensions[epos : epos+extDataLen]
		epos += extDataLen
		if extType != extServerName {
			continue
		}
		// server_name_list: list_len(2) then entries of type(1)+len(2)+name.
		if len(extData) < 2 {
			return "", false
		}
		listLen := int(extData[0])<<8 | int(extData[1])
		list := extData[2:]
		if len(list) < listLen {
			return "", false
		}
		list = list[:listLen]
		lpos := 0
		for lpos+3 <= len(list) {
			nameType := list[lpos]
			nameLen := int(list[lpos+1])<<8 | int(list[lpos+2])
			lpos += 3
			if lpos+nameLen > len(list) {
				return "", false
			}
			name := list[lpos : lpos+nameLen]
			lpos += nameLen
			const hostNameType = 0x00
			if nameType == hostNameType {
				return string(name), true
			}
		}
		return "", false
	}
	return "", false
}

// replayConn wraps a net.Conn so the first Read calls are served from an already-buffered byte
// slice (the bytes peekSNI looked at) before falling through to the real connection — the
// downstream relay never knows anything was inspected first.
type replayConn struct {
	net.Conn
	buffered []byte
}

func (r *replayConn) Read(p []byte) (int, error) {
	if len(r.buffered) > 0 {
		n := copy(p, r.buffered)
		r.buffered = r.buffered[n:]
		return n, nil
	}
	return r.Conn.Read(p)
}
