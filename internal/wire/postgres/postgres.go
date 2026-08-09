// Package postgres implements the PostgreSQL v3 frontend/backend wire protocol as a masking proxy.
//
// Shape: the client connects to us; we dial the upstream DB. The client->server direction is
// forwarded verbatim (we never rewrite queries). The server->client direction is parsed message by
// message; RowDescription ('T') is tracked for column names/formats and DataRow ('D') values are run
// through the masker before being re-encoded and forwarded. Everything else (auth, errors, command
// completion) passes through unchanged.
//
// Client-side SSL: when the engine is built with a TLS config the proxy *terminates* the client's
// SSLRequest (answers 'S' and completes a TLS handshake), so the StartupMessage — and, in the
// credential-injection path, the session token sent as the cleartext password — travel encrypted.
// Without a TLS config the proxy declines SSL ('N') as before. GSSAPI encryption is always declined.
// The proxy still speaks plaintext to the upstream (the agent reaches the DB over the trusted
// in-network path); upstream TLS is a separate later addition.
package postgres

import (
	"bufio"
	"bytes"
	"context"
	"crypto/tls"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"strings"

	"github.com/curlix-io/skybridge/internal/mask"
	"github.com/curlix-io/skybridge/internal/wire"
)

const (
	sslRequestCode    = 80877103
	gssRequestCode    = 80877104
	cancelRequestCode = 80877102
)

var errProtocol = errors.New("postgres: malformed message")

// Engine is the Postgres wire-proxy engine.
type Engine struct {
	// clientTLS, when non-nil, makes the proxy terminate client TLS (answer the SSLRequest with 'S'
	// and complete the handshake) instead of declining it. nil = decline SSL ('N'), as before.
	clientTLS *tls.Config
}

// New returns a Postgres engine that declines client SSL (plaintext client link).
func New() *Engine { return &Engine{} }

// NewWithClientTLS returns a Postgres engine that terminates client TLS using cfg, so the startup
// handshake (and the injected-credential session token) is encrypted on the client link.
func NewWithClientTLS(cfg *tls.Config) *Engine { return &Engine{clientTLS: cfg} }

// Name implements wire.Engine.
func (*Engine) Name() string { return "postgres" }

// Proxy implements wire.Engine.
func (e *Engine) Proxy(ctx context.Context, client, upstream net.Conn, masker mask.Masker, recorder wire.Recorder) error {
	if masker == nil {
		masker = mask.Noop{}
	}
	if recorder == nil {
		recorder = wire.NoopRecorder{}
	}
	client, cr, err := negotiateStartup(client, e.clientTLS)
	if err != nil {
		return err
	}

	errc := make(chan error, 2)
	// client -> server: forward verbatim (the StartupMessage and everything after are buffered in
	// cr), teeing raw bytes into the recorder for replay (opaque/best-effort — not re-parsed here).
	go func() {
		_, err := io.Copy(upstream, io.TeeReader(cr, wire.RecorderInputWriter(recorder)))
		errc <- err
	}()
	// server -> client: parse + mask DataRows.
	go func() {
		errc <- pipeBackend(ctx, upstream, client, masker, recorder)
	}()

	err = <-errc
	_ = client.Close()
	_ = upstream.Close()
	<-errc
	if errors.Is(err, io.EOF) || errors.Is(err, net.ErrClosed) {
		return nil
	}
	return err
}

// ProxyInject implements wire.InjectingEngine: credential handoff (design phase 3). Rather than
// forwarding the client's auth verbatim, the agent terminates the client login locally (cleartext
// password = an opaque session token), resolves an upstream credential via resolve, and
// ORIGINATES its own upstream auth (trust / cleartext / md5 / SCRAM-SHA-256). The client never holds
// a credential the database would accept directly; after upstream auth succeeds, result rows are
// masked exactly as in the verbatim path.
func (e *Engine) ProxyInject(ctx context.Context, client, upstream net.Conn, masker mask.Masker, resolve wire.CredentialResolver, recorder wire.Recorder) error {
	if masker == nil {
		masker = mask.Noop{}
	}
	if recorder == nil {
		recorder = wire.NoopRecorder{}
	}
	if resolve == nil {
		return errors.New("postgres: credential injection requires a resolver")
	}
	client, cr, err := negotiateStartup(client, e.clientTLS)
	if err != nil {
		return err
	}
	startup, err := readStartupParams(cr)
	if err != nil {
		return err
	}
	token, err := requestClientPassword(client, cr)
	if err != nil {
		return err
	}
	cred, err := resolve(ctx, startup, token)
	if err != nil {
		// 28000 = invalid_authorization_specification: a clean "auth failed" for the native client.
		_ = writeClientError(client, "28000", "skybridge: access denied for this session")
		return err
	}

	ur := bufio.NewReaderSize(upstream, 1<<16)
	if err := authenticateUpstream(upstream, ur, cred, startup["database"]); err != nil {
		_ = writeClientError(client, "28000", "skybridge: upstream authentication failed")
		return err
	}
	if err := sendClientAuthOK(client); err != nil {
		return err
	}

	errc := make(chan error, 2)
	// client -> upstream: forward queries verbatim (startup + auth already consumed from cr).
	go func() {
		_, err := io.Copy(upstream, io.TeeReader(cr, wire.RecorderInputWriter(recorder)))
		errc <- err
	}()
	// upstream -> client: parse + mask DataRows, reusing the reader that buffered the post-auth tail.
	go func() {
		errc <- pipeBackendReader(ctx, ur, client, masker, recorder)
	}()

	err = <-errc
	_ = client.Close()
	_ = upstream.Close()
	<-errc
	if errors.Is(err, io.EOF) || errors.Is(err, net.ErrClosed) {
		return nil
	}
	return err
}

// writeClientError sends a FATAL ErrorResponse to the native client (used when login is denied), so
// tools like psql/pgAdmin show a clean authentication failure instead of a dropped connection.
func writeClientError(w io.Writer, sqlstate, message string) error {
	var payload []byte
	add := func(field byte, val string) {
		payload = append(payload, field)
		payload = append(payload, val...)
		payload = append(payload, 0)
	}
	add('S', "FATAL")
	add('V', "FATAL")
	add('C', sqlstate)
	add('M', message)
	payload = append(payload, 0) // terminator
	return writeMessage(w, msgErrorResponse, payload)
}

// negotiateStartup consumes any leading SSLRequest / GSSENCRequest frames from the client. When
// clientTLS is non-nil an SSLRequest is *accepted* ('S') and the connection is upgraded to TLS;
// otherwise SSL is declined ('N'). GSSAPI encryption is always declined. It returns the (possibly
// TLS-wrapped) client connection and a buffered reader positioned at the StartupMessage — the first
// non-negotiation frame is prepended back so the caller can read/forward it intact.
func negotiateStartup(client net.Conn, clientTLS *tls.Config) (net.Conn, *bufio.Reader, error) {
	var hdr [8]byte
	for {
		if _, err := io.ReadFull(client, hdr[:]); err != nil {
			return nil, nil, err
		}
		length := binary.BigEndian.Uint32(hdr[0:4])
		code := binary.BigEndian.Uint32(hdr[4:8])
		if length == 8 && (code == sslRequestCode || code == gssRequestCode) {
			if code == sslRequestCode && clientTLS != nil {
				if _, err := client.Write([]byte{'S'}); err != nil {
					return nil, nil, err
				}
				tconn := tls.Server(client, clientTLS)
				if err := tconn.Handshake(); err != nil {
					return nil, nil, fmt.Errorf("postgres: client TLS handshake failed: %w", err)
				}
				client = tconn // subsequent reads/writes are encrypted
				continue       // read the StartupMessage (sent over TLS) next
			}
			// No TLS configured, or a GSSENCRequest: decline and wait for the next frame.
			if _, err := client.Write([]byte{'N'}); err != nil {
				return nil, nil, err
			}
			continue
		}
		// CancelRequest or a normal StartupMessage: not a negotiation frame. Prepend the 8 bytes we
		// already read so the caller sees the whole message, and hand back a buffered reader.
		cr := bufio.NewReaderSize(io.MultiReader(bytes.NewReader(append([]byte(nil), hdr[:]...)), client), 1<<16)
		return client, cr, nil
	}
}

// pipeBackend reads typed backend messages from server, masks DataRows, and writes to client.
func pipeBackend(ctx context.Context, server io.Reader, client io.Writer, masker mask.Masker, recorder wire.Recorder) error {
	return pipeBackendReader(ctx, bufio.NewReaderSize(server, 1<<16), client, masker, recorder)
}

// pipeBackendReader is pipeBackend over an already-buffered reader. The injection path uses it so
// the post-auth bytes the auth handshake left buffered in br are not lost.
func pipeBackendReader(ctx context.Context, br *bufio.Reader, client io.Writer, masker mask.Masker, recorder wire.Recorder) error {
	bw := bufio.NewWriterSize(client, 1<<16)
	var cols []mask.Column
	header := make([]byte, 5)
	for {
		if _, err := io.ReadFull(br, header); err != nil {
			_ = bw.Flush()
			return err
		}
		typ := header[0]
		length := binary.BigEndian.Uint32(header[1:5]) // length includes itself (4), excludes type
		if length < 4 {
			return errProtocol
		}
		payload := make([]byte, int(length)-4)
		if _, err := io.ReadFull(br, payload); err != nil {
			_ = bw.Flush()
			return err
		}

		switch typ {
		case 'T': // RowDescription
			cols = parseRowDescription(payload)
		case 'D': // DataRow
			masked, values, err := maskDataRow(ctx, payload, cols, masker)
			if err != nil {
				if errors.Is(err, mask.ErrMaskerUnavailable) {
					return err
				}
				// Protocol-parse drift: safe by construction, forward the original bytes unmasked.
				break
			}
			payload = masked
			recorder.RecordOutput(renderRow(cols, values))
		}

		if err := writeMessage(bw, typ, payload); err != nil {
			return err
		}
		// Flush at a query boundary (ReadyForQuery) or whenever the read buffer is drained, to keep
		// interactive latency low without flushing on every row.
		if typ == 'Z' || br.Buffered() == 0 {
			if err := bw.Flush(); err != nil {
				return err
			}
		}
	}
}

func writeMessage(w io.Writer, typ byte, payload []byte) error {
	var hdr [5]byte
	hdr[0] = typ
	binary.BigEndian.PutUint32(hdr[1:5], uint32(len(payload)+4))
	if _, err := w.Write(hdr[:]); err != nil {
		return err
	}
	_, err := w.Write(payload)
	return err
}

// nonFreeTextTypeOIDs are well-known Postgres built-in type OIDs (see pg_type.dat / the "OID"
// column of https://www.postgresql.org/docs/current/datatype-oid.html) whose text-format wire
// representation is a fixed, driver-decoded format — never free-form prose a PII detector should
// scan. A free-text PII detector (Presidio DATE_TIME et al.) confidently misclassifying an ordinary
// timestamp/numeric/uuid value and redacting it produces a value the client's type decoder can no
// longer parse (e.g. psycopg2 raising "unable to parse date"), corrupting the response rather than
// just over-redacting — this is a protocol-correctness bug, not a masking-precision tradeoff, so
// these types are excluded from scanning unconditionally rather than via a configurable allowlist.
// 19 (name) is Postgres's internal catalog-identifier type: pg_class.relname, pg_namespace.nspname,
// pg_proc.proname, etc. — table/column/function/role names. The Studio schema explorer queries
// these system catalogs over this same masked connection to list tables/columns/functions; a table
// name is structural metadata, never user data, and must never be run through a free-text PII
// detector (a real false positive hit this: "access_request_rules" scored as an NRP/nationality-
// religious-political entity and got redacted to "[redacted]" in the explorer sidebar — corrupting
// schema browsing itself, not protecting anything).
var nonFreeTextTypeOIDs = map[uint32]bool{
	16:   true, // bool
	19:   true, // name
	20:   true, // int8
	21:   true, // int2
	23:   true, // int4
	26:   true, // oid
	114:  true, // json
	700:  true, // float4
	701:  true, // float8
	1082: true, // date
	1083: true, // time
	1114: true, // timestamp
	1184: true, // timestamptz
	1186: true, // interval
	1266: true, // timetz
	1700: true, // numeric
	2950: true, // uuid
	3802: true, // jsonb
}

// parseRowDescription extracts column names, text/binary format, and free-text eligibility from a
// 'T' message payload.
func parseRowDescription(p []byte) []mask.Column {
	if len(p) < 2 {
		return nil
	}
	n := int(binary.BigEndian.Uint16(p[0:2]))
	off := 2
	cols := make([]mask.Column, 0, n)
	for i := 0; i < n; i++ {
		end := indexZero(p, off)
		if end < 0 {
			break
		}
		name := string(p[off:end])
		off = end + 1
		// tableOID(4) colAttr(2) typeOID(4) typeSize(2) typeMod(4) formatCode(2) = 18 bytes
		if off+18 > len(p) {
			break
		}
		typeOID := binary.BigEndian.Uint32(p[off+6 : off+10])
		formatCode := binary.BigEndian.Uint16(p[off+16 : off+18])
		off += 18
		cols = append(cols, mask.Column{
			Name:     name,
			Text:     formatCode == 0,
			FreeText: !nonFreeTextTypeOIDs[typeOID],
		})
	}
	return cols
}

// maskDataRow decodes a 'D' payload, runs the masker, and re-encodes it. Also returns the masked
// field values (already decoded here) so the caller can render a replay-transcript line without
// re-parsing the re-encoded payload.
func maskDataRow(ctx context.Context, p []byte, cols []mask.Column, masker mask.Masker) ([]byte, [][]byte, error) {
	if len(p) < 2 {
		return p, nil, nil
	}
	n := int(binary.BigEndian.Uint16(p[0:2]))
	off := 2
	row := make([][]byte, n)
	for i := 0; i < n; i++ {
		if off+4 > len(p) {
			return nil, nil, errProtocol
		}
		flen := int32(binary.BigEndian.Uint32(p[off : off+4]))
		off += 4
		if flen < 0 {
			row[i] = nil
			continue
		}
		if off+int(flen) > len(p) {
			return nil, nil, errProtocol
		}
		v := make([]byte, flen)
		copy(v, p[off:off+int(flen)])
		row[i] = v
		off += int(flen)
	}

	mc := make([]mask.Column, n)
	for i := 0; i < n; i++ {
		if i < len(cols) {
			mc[i] = cols[i]
		} else {
			mc[i] = mask.Column{Text: true, FreeText: true} // unknown column on protocol drift: treat as text
		}
	}
	masked, err := masker.MaskRow(ctx, mc, row)
	if err != nil {
		return nil, nil, err
	}
	if len(masked) != n {
		return nil, nil, errProtocol
	}

	out := make([]byte, 0, len(p))
	var num [2]byte
	binary.BigEndian.PutUint16(num[:], uint16(n))
	out = append(out, num[:]...)
	var l [4]byte
	for i := 0; i < n; i++ {
		if masked[i] == nil {
			binary.BigEndian.PutUint32(l[:], 0xFFFFFFFF) // -1 = NULL
			out = append(out, l[:]...)
			continue
		}
		binary.BigEndian.PutUint32(l[:], uint32(len(masked[i])))
		out = append(out, l[:]...)
		out = append(out, masked[i]...)
	}
	return out, masked, nil
}

// renderRow formats an already-masked row as "col1=val1, col2=val2, ..." for the replay
// transcript — a best-effort human-readable line, not a re-encoding of the wire format.
func renderRow(cols []mask.Column, values [][]byte) string {
	if len(values) == 0 {
		return ""
	}
	var b strings.Builder
	for i, v := range values {
		if i > 0 {
			b.WriteString(", ")
		}
		name := ""
		if i < len(cols) {
			name = cols[i].Name
		}
		if name == "" {
			name = fmt.Sprintf("col%d", i)
		}
		b.WriteString(name)
		b.WriteByte('=')
		if v == nil {
			b.WriteString("NULL")
		} else {
			b.Write(v)
		}
	}
	return b.String()
}

func indexZero(p []byte, from int) int {
	for i := from; i < len(p); i++ {
		if p[i] == 0 {
			return i
		}
	}
	return -1
}
