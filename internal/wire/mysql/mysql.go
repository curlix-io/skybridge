// Package mysql implements the MySQL client/server wire protocol as a masking proxy.
//
// Shape (mirrors the postgres engine): client connects to us, we dial the upstream DB. The
// client->server direction is forwarded verbatim, but we watch it for the start of a text query
// (COM_QUERY, seq 0) so the server->client direction knows the next response is a result set to
// parse + mask. Result-set rows (text protocol) have each field value run through the masker, then
// the row packet is re-framed. Everything else — handshake, auth, OK/ERR, prepared-statement
// (binary protocol) responses — passes through untouched.
//
// Upstream TLS: unlike Postgres (SSLRequest before the protocol) or Mongo (TLS on connect), MySQL
// negotiates TLS *inside* the seq-numbered connection handshake. When the engine is built with an
// upstream tls.Config it therefore drives that negotiation itself: after the client's
// HandshakeResponse it sends its own SSL-request packet to the upstream, completes the TLS handshake,
// re-sends the response over TLS, and then relays the rest of the connection phase with the wire
// sequence id shifted by +1 (the extra packet the agent inserted) until auth completes — after which
// the per-command sequence resets and masking proceeds as usual over the encrypted upstream link.
//
// Limitations (safe by construction — unparsed traffic is forwarded, never corrupted):
//   - Requires plaintext between the client and the agent. If the client negotiates TLS
//     (CLIENT_SSL), the proxy drops to a transparent passthrough (no masking) for that connection.
//   - Binary-protocol result sets (COM_STMT_EXECUTE) are passed through unmasked for now.
//   - Logical packets larger than 16 MiB (multi-packet) are passed through unmasked.
package mysql

import (
	"bufio"
	"context"
	"crypto/tls"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"sync/atomic"

	"github.com/curlix-io/skybridge/internal/mask"
)

const (
	comQuery = 0x03

	capClientSSL          = 0x00000800
	capClientProtocol41   = 0x00000200
	capClientDeprecateEOF = 0x01000000

	pktOK          = 0x00
	pktLocalInfile = 0xFB
	pktEOF         = 0xFE
	pktERR         = 0xFF

	statusMoreResults = 0x0008
	maxPacket         = 0xFFFFFF

	// sslRequestLen is the fixed size of the client SSL-request packet: the leading 32 bytes of a
	// PROTOCOL_41 HandshakeResponse (4 caps + 4 max-packet + 1 charset + 23 reserved), with no
	// username/auth — it tells the server to start TLS now.
	sslRequestLen = 32
)

// Engine is the MySQL wire-proxy engine.
type Engine struct {
	// clientTLS, when non-nil, lets the engine terminate the native client's TLS in the credential-
	// injection path (ProxyInject) — the client presents a curlix session token instead of a DB
	// password, so the link must be encrypted. nil = no client-TLS termination.
	clientTLS *tls.Config
	// upstreamTLS, when non-nil, makes the engine negotiate TLS to the upstream database during the
	// handshake. upstreamRequired fails the session if the server does not advertise SSL (require/
	// verify-*); when false (prefer) the engine falls back to a plaintext upstream.
	upstreamTLS      *tls.Config
	upstreamRequired bool
}

// New returns a MySQL engine (plaintext upstream).
func New() *Engine { return &Engine{} }

// NewWithClientTLS returns a MySQL engine that can terminate client TLS (used by the credential-
// injection path so the session token the client sends is encrypted).
func NewWithClientTLS(cfg *tls.Config) *Engine { return &Engine{clientTLS: cfg} }

// WithUpstreamTLS returns a copy of the engine that negotiates TLS to the upstream using cfg. cfg
// carries the verification posture (ServerName / RootCAs / InsecureSkipVerify) for the upstream host.
func (e *Engine) WithUpstreamTLS(cfg *tls.Config, required bool) *Engine {
	c := *e
	c.upstreamTLS = cfg
	c.upstreamRequired = required
	return &c
}

// Name implements wire.Engine.
func (*Engine) Name() string { return "mysql" }

type state struct {
	caps    uint32 // client-chosen capability flags (immutable after handshake)
	queries chan struct{}
	// offset is the wire sequence-id shift applied while the agent has inserted an extra packet into
	// the connection phase (upstream TLS): client→server packets get +offset, server→client packets
	// get −offset. It starts at 1 in that case and drops to 0 once auth completes (after which each
	// command resets the sequence to 0). Zero throughout the plaintext-upstream path.
	offset atomic.Int32
}

func (s *state) deprecateEOF() bool { return s.caps&capClientDeprecateEOF != 0 }

// Proxy implements wire.Engine.
func (e *Engine) Proxy(ctx context.Context, client, upstream net.Conn, masker mask.Masker) error {
	if masker == nil {
		masker = mask.Noop{}
	}
	cb := bufio.NewReaderSize(client, 1<<16)
	sb := bufio.NewReaderSize(upstream, 1<<16)

	// Handshake is lock-step: server Initial Handshake -> client, then client Handshake Response.
	greetSeq, greeting, _, err := readPacket(sb)
	if err != nil {
		return err
	}
	if err := writePacket(client, greetSeq, greeting); err != nil {
		return err
	}
	cseq, cpayload, _, err := readPacket(cb)
	if err != nil {
		return err
	}
	var caps uint32
	if len(cpayload) >= 4 {
		caps = binary.LittleEndian.Uint32(cpayload[:4])
	}
	if caps&capClientSSL != 0 {
		// The client itself negotiated TLS to us; the stream is encrypted and we cannot parse it.
		// Forward verbatim (no masking, no upstream-TLS interception).
		if err := writePacket(upstream, cseq, cpayload); err != nil {
			return err
		}
		return passthrough(cb, sb, client, upstream)
	}

	var offset int32
	if e.upstreamTLS != nil {
		upstream, sb, offset, err = e.startUpstreamTLS(upstream, greeting, cseq, cpayload, caps)
		if err != nil {
			return err
		}
	} else if err := writePacket(upstream, cseq, cpayload); err != nil {
		return err
	}

	s := &state{caps: caps, queries: make(chan struct{}, 64)}
	s.offset.Store(offset)
	errc := make(chan error, 2)
	go func() { errc <- s.clientToServer(cb, upstream) }()
	go func() { errc <- s.serverToClient(ctx, sb, client, masker) }()
	err = <-errc
	_ = client.Close()
	_ = upstream.Close()
	<-errc
	if errors.Is(err, io.EOF) || errors.Is(err, net.ErrClosed) {
		return nil
	}
	return err
}

// startUpstreamTLS negotiates TLS with the upstream during the connection handshake. The client's
// HandshakeResponse (cseq/cpayload) has already been read but not yet forwarded. It sends an
// SSL-request packet (seq cseq), completes the TLS handshake, re-sends the response with CLIENT_SSL
// set as seq cseq+1, and returns the TLS-wrapped upstream conn, a reader over it, and the sequence
// offset (1) to apply for the remainder of the connection phase. When the server does not advertise
// SSL it errors (require/verify-*) or falls back to a plaintext upstream (prefer, offset 0).
func (e *Engine) startUpstreamTLS(upstream net.Conn, greeting []byte, cseq byte, cpayload []byte, caps uint32) (net.Conn, *bufio.Reader, int32, error) {
	canTLS := serverSupportsSSL(greeting) && caps&capClientProtocol41 != 0 && len(cpayload) >= sslRequestLen
	if !canTLS {
		if e.upstreamRequired {
			return nil, nil, 0, fmt.Errorf("mysql: upstream TLS required but %s", tlsUnavailableReason(greeting, caps, cpayload))
		}
		// prefer: continue plaintext.
		if err := writePacket(upstream, cseq, cpayload); err != nil {
			return nil, nil, 0, err
		}
		return upstream, bufio.NewReaderSize(upstream, 1<<16), 0, nil
	}

	// SSL-request packet: the first 32 bytes of the response (caps/max-packet/charset/reserved) with
	// CLIENT_SSL forced on, no username/auth. Same seq as the client's response (the first client
	// packet); the full response then follows as the next sequence id over TLS.
	sslReq := make([]byte, sslRequestLen)
	copy(sslReq, cpayload[:sslRequestLen])
	binary.LittleEndian.PutUint32(sslReq[0:4], caps|capClientSSL)
	if err := writePacket(upstream, cseq, sslReq); err != nil {
		return nil, nil, 0, err
	}
	tconn := tls.Client(upstream, e.upstreamTLS)
	if err := tconn.Handshake(); err != nil {
		return nil, nil, 0, fmt.Errorf("mysql: upstream TLS handshake failed: %w", err)
	}
	// Re-send the full HandshakeResponse over TLS with CLIENT_SSL set, as the next sequence id.
	full := make([]byte, len(cpayload))
	copy(full, cpayload)
	binary.LittleEndian.PutUint32(full[0:4], caps|capClientSSL)
	if err := writePacket(tconn, cseq+1, full); err != nil {
		return nil, nil, 0, err
	}
	return tconn, bufio.NewReaderSize(tconn, 1<<16), 1, nil
}

func tlsUnavailableReason(greeting []byte, caps uint32, cpayload []byte) string {
	switch {
	case !serverSupportsSSL(greeting):
		return "the server does not advertise CLIENT_SSL"
	case caps&capClientProtocol41 == 0:
		return "the client is not using PROTOCOL_41"
	case len(cpayload) < sslRequestLen:
		return "the client handshake response is too short to derive an SSL request"
	default:
		return "TLS is unavailable"
	}
}

// serverSupportsSSL reports whether a v10 Initial Handshake packet advertises CLIENT_SSL.
func serverSupportsSSL(greeting []byte) bool {
	if len(greeting) == 0 || greeting[0] != 0x0a { // protocol version 10
		return false
	}
	off := 1
	for off < len(greeting) && greeting[off] != 0 { // server version cstring
		off++
	}
	off++            // NUL
	off += 4 + 8 + 1 // connection id + auth-plugin-data-part-1 + filler
	if off+2 > len(greeting) {
		return false
	}
	lowerCaps := binary.LittleEndian.Uint16(greeting[off : off+2])
	return uint32(lowerCaps)&capClientSSL != 0
}

func passthrough(cb *bufio.Reader, sb *bufio.Reader, client, upstream net.Conn) error {
	errc := make(chan error, 2)
	go func() { _, e := io.Copy(upstream, cb); errc <- e }()
	go func() { _, e := io.Copy(client, sb); errc <- e }()
	e := <-errc
	_ = client.Close()
	_ = upstream.Close()
	<-errc
	if errors.Is(e, io.EOF) || errors.Is(e, net.ErrClosed) {
		return nil
	}
	return e
}

// clientToServer forwards verbatim and flags COM_QUERY so the response side parses the result set.
// During the connection phase of an upstream-TLS session it shifts the sequence id by +offset to
// account for the SSL-request packet the agent inserted.
func (s *state) clientToServer(cb *bufio.Reader, upstream io.Writer) error {
	for {
		seq, payload, full, err := readPacket(cb)
		if err != nil {
			return err
		}
		if !full && seq == 0 && len(payload) > 0 && payload[0] == comQuery {
			select {
			case s.queries <- struct{}{}:
			default:
			}
		}
		if err := writePacket(upstream, seq+byte(s.offset.Load()), payload); err != nil {
			return err
		}
	}
}

func (s *state) serverToClient(ctx context.Context, sb *bufio.Reader, client io.Writer, masker mask.Masker) error {
	bw := bufio.NewWriterSize(client, 1<<16)
	// Connection phase (only entered when the agent inserted an SSL-request packet for upstream TLS):
	// relay auth packets with the sequence id shifted back by −offset until the auth result (OK/ERR),
	// then drop the offset to 0 so the per-command sequence ids line up for masking below.
	for s.offset.Load() != 0 {
		seq, payload, _, err := readPacket(sb)
		if err != nil {
			_ = bw.Flush()
			return err
		}
		done := len(payload) > 0 && (payload[0] == pktOK || payload[0] == pktERR)
		if done {
			s.offset.Store(0) // before the write, so client→server commands that follow use offset 0
		}
		if err := writePacket(bw, seq-1, payload); err != nil { // offset was 1 throughout this phase
			return err
		}
		// Flush each auth packet so the client can respond (the handshake is lock-step).
		if err := bw.Flush(); err != nil {
			return err
		}
		if done {
			break
		}
	}
	for {
		seq, payload, full, err := readPacket(sb)
		if err != nil {
			_ = bw.Flush()
			return err
		}
		pending := false
		select {
		case <-s.queries:
			pending = true
		default:
		}
		if pending && !full {
			if err := s.handleResultResponse(ctx, sb, bw, masker, seq, payload); err != nil {
				_ = bw.Flush()
				return err
			}
			if err := bw.Flush(); err != nil {
				return err
			}
			continue
		}
		if err := writePacket(bw, seq, payload); err != nil {
			return err
		}
		if sb.Buffered() == 0 {
			if err := bw.Flush(); err != nil {
				return err
			}
		}
	}
}

// handleResultResponse consumes one (or more, for multi-statement) result sets, masking rows.
// first{Seq,Payload} is the first packet of the response, already read by the caller.
func (s *state) handleResultResponse(ctx context.Context, sb *bufio.Reader, bw *bufio.Writer, masker mask.Masker, firstSeq byte, firstPayload []byte) error {
	seq, payload := firstSeq, firstPayload
	for {
		more, done, err := s.handleOneResultSet(ctx, sb, bw, masker, seq, payload)
		if err != nil || done || !more {
			return err
		}
		// Another result set follows (multi-statement): read its first packet and loop.
		seq, payload, _, err = readPacket(sb)
		if err != nil {
			return err
		}
	}
}

// handleOneResultSet processes a single response whose first packet is first{Seq,Payload}. It
// returns more=true when SERVER_MORE_RESULTS_EXISTS was set on the terminator, and done=true when
// the response was a non-result-set reply (OK/ERR) or it fell back to raw forwarding.
func (s *state) handleOneResultSet(ctx context.Context, sb *bufio.Reader, bw *bufio.Writer, masker mask.Masker, seq byte, payload []byte) (more bool, done bool, err error) {
	// Non-result-set response (OK/ERR/LOCAL INFILE): forward and we're done.
	if len(payload) == 0 || payload[0] == pktOK || payload[0] == pktERR || payload[0] == pktLocalInfile {
		return false, true, writePacket(bw, seq, payload)
	}
	// Otherwise the first packet is the column count (lenenc int).
	colCount, _, ok := readLenEncInt(payload, 0)
	if !ok {
		return false, true, writePacket(bw, seq, payload)
	}
	if err := writePacket(bw, seq, payload); err != nil {
		return false, false, err
	}

	cols := make([]mask.Column, 0, colCount)
	for i := uint64(0); i < colCount; i++ {
		cseq, cpayload, full, err := readPacket(sb)
		if err != nil {
			return false, false, err
		}
		if full {
			if err := writePacket(bw, cseq, cpayload); err != nil {
				return false, false, err
			}
			return false, true, forwardRest(sb, bw)
		}
		cols = append(cols, mask.Column{Name: columnName(cpayload), Text: true})
		if err := writePacket(bw, cseq, cpayload); err != nil {
			return false, false, err
		}
	}

	// Pre-DEPRECATE_EOF protocols send an EOF after the column definitions.
	if !s.deprecateEOF() {
		eseq, epayload, _, err := readPacket(sb)
		if err != nil {
			return false, false, err
		}
		if err := writePacket(bw, eseq, epayload); err != nil {
			return false, false, err
		}
	}

	// Rows until the terminating EOF/OK.
	for {
		rseq, rpayload, full, err := readPacket(sb)
		if err != nil {
			return false, false, err
		}
		if full {
			if err := writePacket(bw, rseq, rpayload); err != nil {
				return false, false, err
			}
			return false, true, forwardRest(sb, bw)
		}
		if isTerminator(rpayload, s.deprecateEOF()) {
			more = resultStatus(rpayload, s.deprecateEOF())&statusMoreResults != 0
			return more, false, writePacket(bw, rseq, rpayload)
		}
		if newPayload, ok := maskTextRow(ctx, rpayload, cols, masker); ok && len(newPayload) < maxPacket {
			rpayload = newPayload
		}
		if err := writePacket(bw, rseq, rpayload); err != nil {
			return false, false, err
		}
	}
}

func forwardRest(sb *bufio.Reader, bw *bufio.Writer) error {
	if err := bw.Flush(); err != nil {
		return err
	}
	_, err := io.Copy(bw, sb)
	if err != nil {
		return err
	}
	return bw.Flush()
}

// ---- protocol helpers ----

func readPacket(r *bufio.Reader) (seq byte, payload []byte, full bool, err error) {
	var hdr [4]byte
	if _, err = io.ReadFull(r, hdr[:]); err != nil {
		return 0, nil, false, err
	}
	n := int(hdr[0]) | int(hdr[1])<<8 | int(hdr[2])<<16
	seq = hdr[3]
	payload = make([]byte, n)
	if _, err = io.ReadFull(r, payload); err != nil {
		return 0, nil, false, err
	}
	return seq, payload, n == maxPacket, nil
}

func writePacket(w io.Writer, seq byte, payload []byte) error {
	n := len(payload)
	if _, err := w.Write([]byte{byte(n), byte(n >> 8), byte(n >> 16), seq}); err != nil {
		return err
	}
	_, err := w.Write(payload)
	return err
}

func readLenEncInt(p []byte, off int) (val uint64, n int, ok bool) {
	if off >= len(p) {
		return 0, 0, false
	}
	switch b := p[off]; {
	case b < 0xFB:
		return uint64(b), 1, true
	case b == 0xFC:
		if off+3 > len(p) {
			return 0, 0, false
		}
		return uint64(p[off+1]) | uint64(p[off+2])<<8, 3, true
	case b == 0xFD:
		if off+4 > len(p) {
			return 0, 0, false
		}
		return uint64(p[off+1]) | uint64(p[off+2])<<8 | uint64(p[off+3])<<16, 4, true
	case b == 0xFE:
		if off+9 > len(p) {
			return 0, 0, false
		}
		return binary.LittleEndian.Uint64(p[off+1 : off+9]), 9, true
	default: // 0xFB (NULL) / 0xFF are not valid lengths in this context
		return 0, 0, false
	}
}

func appendLenEncInt(b []byte, v uint64) []byte {
	switch {
	case v < 0xFB:
		return append(b, byte(v))
	case v <= 0xFFFF:
		return append(b, 0xFC, byte(v), byte(v>>8))
	case v <= 0xFFFFFF:
		return append(b, 0xFD, byte(v), byte(v>>8), byte(v>>16))
	default:
		var t [8]byte
		binary.LittleEndian.PutUint64(t[:], v)
		return append(append(b, 0xFE), t[:]...)
	}
}

// lenEncStrSpan returns the total bytes a lenenc string occupies at off.
func lenEncStrSpan(p []byte, off int) (int, bool) {
	l, n, ok := readLenEncInt(p, off)
	if !ok {
		return 0, false
	}
	total := n + int(l)
	if off+total > len(p) {
		return 0, false
	}
	return total, true
}

// columnName extracts the column name (5th lenenc string) from a PROTOCOL_41 column-definition packet.
func columnName(p []byte) string {
	off := 0
	for i := 0; i < 4; i++ { // catalog, schema, table, org_table
		span, ok := lenEncStrSpan(p, off)
		if !ok {
			return ""
		}
		off += span
	}
	l, n, ok := readLenEncInt(p, off)
	if !ok {
		return ""
	}
	off += n
	if off+int(l) > len(p) {
		return ""
	}
	return string(p[off : off+int(l)])
}

// isTerminator reports whether a result-set packet is the closing EOF (classic) or OK (DEPRECATE_EOF).
// A text row never begins with 0xFE (that would encode a >16 MiB first field), so this is unambiguous.
func isTerminator(p []byte, deprecateEOF bool) bool {
	if len(p) == 0 || p[0] != pktEOF {
		return false
	}
	return deprecateEOF || len(p) < 9
}

// resultStatus extracts the status flags from a terminating EOF/OK packet (for SERVER_MORE_RESULTS).
func resultStatus(p []byte, deprecateEOF bool) uint16 {
	if len(p) == 0 || p[0] != pktEOF {
		return 0
	}
	if !deprecateEOF { // EOF: header(1) warnings(2) status(2)
		if len(p) >= 5 {
			return uint16(p[3]) | uint16(p[4])<<8
		}
		return 0
	}
	// OK: header(1) affected_rows(lenenc) last_insert_id(lenenc) status(2)
	off := 1
	_, n, ok := readLenEncInt(p, off)
	if !ok {
		return 0
	}
	off += n
	_, n, ok = readLenEncInt(p, off)
	if !ok {
		return 0
	}
	off += n
	if off+2 <= len(p) {
		return uint16(p[off]) | uint16(p[off+1])<<8
	}
	return 0
}

// maskTextRow decodes a text-protocol row, masks each field, and re-encodes it. Returns ok=false to
// signal the caller to forward the original packet unchanged.
func maskTextRow(ctx context.Context, payload []byte, cols []mask.Column, masker mask.Masker) ([]byte, bool) {
	vals := make([][]byte, 0, len(cols))
	off := 0
	for off < len(payload) {
		if payload[off] == 0xFB { // NULL
			vals = append(vals, nil)
			off++
			continue
		}
		l, n, ok := readLenEncInt(payload, off)
		if !ok {
			return nil, false
		}
		off += n
		if off+int(l) > len(payload) {
			return nil, false
		}
		v := make([]byte, l)
		copy(v, payload[off:off+int(l)])
		vals = append(vals, v)
		off += int(l)
	}

	mc := make([]mask.Column, len(vals))
	for i := range vals {
		if i < len(cols) {
			mc[i] = cols[i]
		} else {
			mc[i] = mask.Column{Text: true}
		}
	}
	masked, err := masker.MaskRow(ctx, mc, vals)
	if err != nil || len(masked) != len(vals) {
		return nil, false
	}

	out := make([]byte, 0, len(payload))
	for _, v := range masked {
		if v == nil {
			out = append(out, 0xFB)
			continue
		}
		out = appendLenEncInt(out, uint64(len(v)))
		out = append(out, v...)
	}
	return out, true
}
