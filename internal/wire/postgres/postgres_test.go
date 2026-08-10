package postgres

import (
	"bufio"
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"strings"
	"testing"

	"github.com/curlix-io/skybridge/internal/mask"
	"github.com/curlix-io/skybridge/internal/wire"
)

// rowDescription builds a 'T' message payload for the given text-format column names, all typed
// as the untyped/unknown OID (0) — i.e. free-text-eligible, matching prior test behavior.
func rowDescriptionPayload(names ...string) []byte {
	oids := make([]uint32, len(names))
	return rowDescriptionPayloadTyped(names, oids)
}

// rowDescriptionPayloadTyped is rowDescriptionPayload plus an explicit Postgres type OID per
// column, for exercising nonFreeTextTypeOIDs handling (e.g. 1184 = timestamptz).
func rowDescriptionPayloadTyped(names []string, oids []uint32) []byte {
	buf := new(bytes.Buffer)
	var u16 [2]byte
	binary.BigEndian.PutUint16(u16[:], uint16(len(names)))
	buf.Write(u16[:])
	for i, n := range names {
		buf.WriteString(n)
		buf.WriteByte(0)
		buf.Write(make([]byte, 6)) // tableOID(4) colAttr(2)
		var oidBytes [4]byte
		binary.BigEndian.PutUint32(oidBytes[:], oids[i])
		buf.Write(oidBytes[:])
		buf.Write(make([]byte, 6)) // typeSize(2) typeMod(4)
		buf.Write([]byte{0, 0})    // formatCode 0 = text
	}
	return buf.Bytes()
}

// dataRowPayload builds a 'D' message payload; a nil value encodes SQL NULL.
func dataRowPayload(vals ...[]byte) []byte {
	buf := new(bytes.Buffer)
	var u16 [2]byte
	binary.BigEndian.PutUint16(u16[:], uint16(len(vals)))
	buf.Write(u16[:])
	var u32 [4]byte
	for _, v := range vals {
		if v == nil {
			binary.BigEndian.PutUint32(u32[:], 0xFFFFFFFF)
			buf.Write(u32[:])
			continue
		}
		binary.BigEndian.PutUint32(u32[:], uint32(len(v)))
		buf.Write(u32[:])
		buf.Write(v)
	}
	return buf.Bytes()
}

func TestParseRowDescription(t *testing.T) {
	cols := parseRowDescription(context.Background(), rowDescriptionPayload("id", "email", "name"), nil)
	if len(cols) != 3 {
		t.Fatalf("want 3 cols, got %d", len(cols))
	}
	if cols[1].Name != "email" || !cols[1].Text {
		t.Fatalf("unexpected col: %+v", cols[1])
	}
	if !cols[1].FreeText {
		t.Fatalf("untyped/unknown-OID column should default free-text eligible: %+v", cols[1])
	}
}

// TestParseRowDescriptionExcludesTypedColumnsFromFreeText is the regression test for the actual
// production bug this typeOID plumbing fixes: Presidio's DATE_TIME recognizer confidently flags an
// ordinary timestamptz value (e.g. "2024-07-05 00:13:50.654762+00:00") as PII and redacts it, but a
// client type-decoding that column (psycopg2 et al.) then fails with "unable to parse date" trying
// to parse the redaction placeholder as a timestamp — corrupting the response, not just
// over-masking. A typed column must never be marked FreeText so no detector ever runs against it.
func TestParseRowDescriptionExcludesTypedColumnsFromFreeText(t *testing.T) {
	names := []string{"id", "created_at", "note", "amount", "is_active"}
	oids := []uint32{23, 1184, 25, 1700, 16} // int4, timestamptz, text, numeric, bool
	cols := parseRowDescription(context.Background(), rowDescriptionPayloadTyped(names, oids), nil)
	if len(cols) != 5 {
		t.Fatalf("want 5 cols, got %d", len(cols))
	}
	want := map[string]bool{
		"id":         false,
		"created_at": false,
		"note":       true,
		"amount":     false,
		"is_active":  false,
	}
	for _, c := range cols {
		if c.FreeText != want[c.Name] {
			t.Errorf("col %q: FreeText=%v, want %v", c.Name, c.FreeText, want[c.Name])
		}
	}
}

// TestParseRowDescriptionExcludesCatalogNameType is the regression test for a second, related
// production bug found via the same session: Postgres's Studio schema explorer (list
// tables/columns/functions) queries system catalogs — pg_class.relname, pg_namespace.nspname,
// pg_proc.proname, etc., all typed OID 19 ("name") — over this same masked connection. A table
// name is structural metadata, never user data; without this exclusion Presidio's NRP (nationality/
// religious/political) recognizer confidently misclassified the real table name
// "access_request_rules" as PII and redacted it to "[redacted]" in the explorer sidebar itself.
func TestParseRowDescriptionExcludesCatalogNameType(t *testing.T) {
	names := []string{"relname", "nspname"}
	oids := []uint32{19, 19} // Postgres "name" type
	cols := parseRowDescription(context.Background(), rowDescriptionPayloadTyped(names, oids), nil)
	for _, c := range cols {
		if c.FreeText {
			t.Errorf("col %q (Postgres name type): FreeText=true, want false", c.Name)
		}
	}
}

// TestMaskDataRowNeverRedactsTypedTimestampColumn exercises the full pipeline (RowDescription ->
// DataRow) with a masker that mimics Presidio's real DATE_TIME false positive, confirming the
// typed column is protected end-to-end, not just at the parseRowDescription layer.
func TestMaskDataRowNeverRedactsTypedTimestampColumn(t *testing.T) {
	names := []string{"created_at", "note"}
	oids := []uint32{1184, 25} // timestamptz, text
	cols := parseRowDescription(context.Background(), rowDescriptionPayloadTyped(names, oids), nil)

	dateTimeLikeValue := []byte("2024-07-05 00:13:50.654762+00:00")
	payload := dataRowPayload(dateTimeLikeValue, []byte("2024-07-05 is my note"))
	// dateTimeGuessingMasker redacts ANY free-text value that looks date-shaped, mimicking
	// Presidio's DATE_TIME recognizer's real-world false-positive behavior on ordinary timestamps.
	masker := dateTimeGuessingMasker{}

	out, values, err := maskDataRow(context.Background(), payload, cols, masker)
	if err != nil {
		t.Fatal(err)
	}
	_ = out
	if string(values[0]) != string(dateTimeLikeValue) {
		t.Fatalf("typed timestamptz column must never be redacted, got %q", values[0])
	}
	if string(values[1]) == "2024-07-05 is my note" {
		t.Fatal("free-text column should have been redacted by the detector in this test")
	}
}

// dateTimeGuessingMasker redacts any free-text column value containing a date-shaped substring —
// standing in for Presidio's real DATE_TIME recognizer without a network call in this test.
type dateTimeGuessingMasker struct{}

func (dateTimeGuessingMasker) MaskRow(_ context.Context, cols []mask.Column, row [][]byte) ([][]byte, error) {
	for i := range row {
		if row[i] == nil || i >= len(cols) || !cols[i].Text || !cols[i].FreeText {
			continue
		}
		if strings.Contains(string(row[i]), "2024-07-05") {
			row[i] = []byte("<DATE_TIME>")
		}
	}
	return row, nil
}

// columnMasker redacts any field whose column name is in the set.
type columnMasker struct{ redact map[string]bool }

func (c columnMasker) MaskRow(_ context.Context, cols []mask.Column, row [][]byte) ([][]byte, error) {
	for i := range row {
		if row[i] == nil {
			continue
		}
		if i < len(cols) && c.redact[strings.ToLower(cols[i].Name)] {
			row[i] = []byte("***")
		}
	}
	return row, nil
}

func TestMaskDataRowRedactsNamedColumn(t *testing.T) {
	cols := parseRowDescription(context.Background(), rowDescriptionPayload("id", "email"), nil)
	payload := dataRowPayload([]byte("7"), []byte("a@b.com"))
	masker := columnMasker{redact: map[string]bool{"email": true}}

	out, _, err := maskDataRow(context.Background(), payload, cols, masker)
	if err != nil {
		t.Fatal(err)
	}
	// Decode and check: id unchanged, email redacted.
	n := int(binary.BigEndian.Uint16(out[0:2]))
	if n != 2 {
		t.Fatalf("want 2 fields, got %d", n)
	}
	off := 2
	get := func() []byte {
		l := int32(binary.BigEndian.Uint32(out[off : off+4]))
		off += 4
		if l < 0 {
			return nil
		}
		v := out[off : off+int(l)]
		off += int(l)
		return v
	}
	if string(get()) != "7" {
		t.Fatal("id should be unchanged")
	}
	if string(get()) != "***" {
		t.Fatal("email should be redacted")
	}
}

func TestMaskDataRowPreservesNull(t *testing.T) {
	cols := parseRowDescription(context.Background(), rowDescriptionPayload("id", "email"), nil)
	payload := dataRowPayload([]byte("7"), nil)
	out, _, err := maskDataRow(context.Background(), payload, cols, mask.Noop{})
	if err != nil {
		t.Fatal(err)
	}
	off := 2 + 4 + 1 // count + id len + "7"
	flen := int32(binary.BigEndian.Uint32(out[off : off+4]))
	if flen != -1 {
		t.Fatalf("null should round-trip as -1, got %d", flen)
	}
}

// TestPipeBackendMasksStream feeds T, D, D, Z and asserts DataRows are masked and other messages
// pass through untouched.
func TestPipeBackendMasksStream(t *testing.T) {
	server := new(bytes.Buffer)
	writeRaw := func(typ byte, payload []byte) {
		var hdr [5]byte
		hdr[0] = typ
		binary.BigEndian.PutUint32(hdr[1:5], uint32(len(payload)+4))
		server.Write(hdr[:])
		server.Write(payload)
	}
	writeRaw('T', rowDescriptionPayload("id", "email"))
	writeRaw('D', dataRowPayload([]byte("1"), []byte("alice@x.com")))
	writeRaw('D', dataRowPayload([]byte("2"), []byte("bob@x.com")))
	writeRaw('Z', []byte{'I'}) // ReadyForQuery (idle)

	client := new(bytes.Buffer)
	masker := columnMasker{redact: map[string]bool{"email": true}}
	err := pipeBackend(context.Background(), bytes.NewReader(server.Bytes()), client, masker, wire.NoopRecorder{}, nil)
	if err == nil || err.Error() != "EOF" {
		t.Fatalf("expected EOF at stream end, got %v", err)
	}

	// The client stream must contain redacted emails and no plaintext addresses.
	out := client.Bytes()
	if bytes.Contains(out, []byte("alice@x.com")) || bytes.Contains(out, []byte("bob@x.com")) {
		t.Fatal("plaintext email leaked through the proxy")
	}
	if !bytes.Contains(out, []byte("***")) {
		t.Fatal("expected redaction token in output")
	}
	// Sanity: output should still parse as a sequence of typed messages ending in 'Z'.
	br := bufio.NewReader(bytes.NewReader(out))
	var last byte
	hdr := make([]byte, 5)
	for {
		if _, e := readFull(br, hdr); e != nil {
			break
		}
		last = hdr[0]
		l := binary.BigEndian.Uint32(hdr[1:5])
		skip := make([]byte, int(l)-4)
		if _, e := readFull(br, skip); e != nil {
			break
		}
	}
	if last != 'Z' {
		t.Fatalf("stream should end with ReadyForQuery, last=%c", last)
	}
}

// errMasker always fails, simulating a masking-service outage under strict mode.
type errMasker struct{}

func (errMasker) MaskRow(context.Context, []mask.Column, [][]byte) ([][]byte, error) {
	return nil, mask.ErrMaskerUnavailable
}

func TestPipeBackendAbortsOnMaskerFailure(t *testing.T) {
	server := new(bytes.Buffer)
	writeRaw := func(typ byte, payload []byte) {
		var hdr [5]byte
		hdr[0] = typ
		binary.BigEndian.PutUint32(hdr[1:5], uint32(len(payload)+4))
		server.Write(hdr[:])
		server.Write(payload)
	}
	writeRaw('T', rowDescriptionPayload("id", "email"))
	writeRaw('D', dataRowPayload([]byte("1"), []byte("alice@x.com")))
	writeRaw('Z', []byte{'I'})

	client := new(bytes.Buffer)
	err := pipeBackend(context.Background(), bytes.NewReader(server.Bytes()), client, errMasker{}, wire.NoopRecorder{}, nil)
	if !errors.Is(err, mask.ErrMaskerUnavailable) {
		t.Fatalf("expected ErrMaskerUnavailable, got %v", err)
	}
	if bytes.Contains(client.Bytes(), []byte("alice@x.com")) {
		t.Fatal("unmasked email must never reach the client when the masker fails in strict mode")
	}
}

// failWriter fails once n bytes have been written across all calls — used to exercise the write-
// error branches of writeMessage/writeClientError/writeFrontend without a real broken pipe.
type failWriter struct{ n int }

func (w *failWriter) Write(p []byte) (int, error) {
	if w.n <= 0 {
		return 0, errors.New("failWriter: write failed")
	}
	if len(p) > w.n {
		n := w.n
		w.n = 0
		return n, errors.New("failWriter: short write")
	}
	w.n -= len(p)
	return len(p), nil
}

// TestNew_DeclinesSSLByDefault verifies New()'s zero-value shape: no client TLS, no orgID scoping,
// no catalog resolver — the safe no-op configuration this package has always defaulted to.
func TestNew_DeclinesSSLByDefault(t *testing.T) {
	e := New()
	if e.clientTLS != nil {
		t.Fatal("New() must not configure client TLS")
	}
	if e.Name() != "postgres" {
		t.Fatalf("Name() = %q, want postgres", e.Name())
	}
	if e.objectIDFor("db") != nil {
		t.Fatal("an engine with no orgID/catalog resolver must resolve no ObjectIDs")
	}
}

// TestWithOrgID_CopiesRatherThanMutates confirms WithOrgID returns an independent copy, so a shared
// base *Engine (e.g. one built once at startup) isn't mutated by a later per-connection call.
func TestWithOrgID_CopiesRatherThanMutates(t *testing.T) {
	base := New()
	scoped := base.WithOrgID("acme")
	if base.orgID != "" {
		t.Fatal("WithOrgID must not mutate the receiver")
	}
	if scoped.orgID != "acme" {
		t.Fatalf("scoped.orgID = %q, want acme", scoped.orgID)
	}
}

// TestWithCatalogResolver_CopiesRatherThanMutates mirrors TestWithOrgID_CopiesRatherThanMutates for
// the catalog-resolver setter.
func TestWithCatalogResolver_CopiesRatherThanMutates(t *testing.T) {
	base := New()
	resolver := NewCatalogResolver(CatalogCredential{Host: "127.0.0.1", Port: "1"})
	scoped := base.WithCatalogResolver(resolver)
	if base.catalog != nil {
		t.Fatal("WithCatalogResolver must not mutate the receiver")
	}
	if scoped.catalog != resolver {
		t.Fatal("scoped engine should carry the given resolver")
	}
}

// TestWriteClientError builds a FATAL ErrorResponse and confirms it round-trips through the same
// message framing the rest of the package uses to read backend messages.
func TestWriteClientError(t *testing.T) {
	var buf bytes.Buffer
	if err := writeClientError(&buf, "28000", "skybridge: access denied for this session"); err != nil {
		t.Fatalf("writeClientError: %v", err)
	}
	br := bufio.NewReader(&buf)
	typ, payload, err := readBackendMessage(br)
	if err != nil {
		t.Fatalf("readBackendMessage: %v", err)
	}
	if typ != msgErrorResponse {
		t.Fatalf("typ = %q, want ErrorResponse", string(rune(typ)))
	}
	got := parseErrorResponse(payload)
	if got != "skybridge: access denied for this session" {
		t.Fatalf("message = %q", got)
	}
}

// TestWriteClientError_WriteFailurePropagates exercises the write-error return path.
func TestWriteClientError_WriteFailurePropagates(t *testing.T) {
	w := &failWriter{n: 0}
	if err := writeClientError(w, "28000", "denied"); err == nil {
		t.Fatal("expected an error when the underlying writer fails")
	}
}

// TestObjectIDFor_UnconfiguredCombinations exercises every "not fully configured" branch of
// objectIDFor: each must return nil (no resolver), matching the documented "unresolved ObjectID,
// skip straight to the overlay layer" fallback — never an error, never a lookup attempt.
func TestObjectIDFor_UnconfiguredCombinations(t *testing.T) {
	resolver := NewCatalogResolver(CatalogCredential{Host: "127.0.0.1", Port: "1"})
	cases := []struct {
		name string
		e    *Engine
		db   string
	}{
		{"no orgID, no catalog", New(), "shop"},
		{"orgID only", New().WithOrgID("acme"), "shop"},
		{"catalog only", New().WithCatalogResolver(resolver), "shop"},
		{"orgID+catalog but empty database", New().WithOrgID("acme").WithCatalogResolver(resolver), ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := tc.e.objectIDFor(tc.db); got != nil {
				t.Fatalf("objectIDFor(%q) = non-nil, want nil (unconfigured)", tc.db)
			}
		})
	}
}

// TestObjectIDFor_ResolvesScopedObjectID is the fully-configured happy path: orgID + catalog
// resolver + non-empty database must produce "orgID:postgres:schema:table" for a resolvable OID and
// "" for an unresolvable one (catalog miss), matching REDACTION.md's table-identity resolution.
func TestObjectIDFor_ResolvesScopedObjectID(t *testing.T) {
	addr, closeFn := fakeCatalogServer(t, "orders", "shop")
	defer closeFn()
	host, port, err := net.SplitHostPort(addr)
	if err != nil {
		t.Fatalf("split addr: %v", err)
	}
	e := New().WithOrgID("acme").WithCatalogResolver(NewCatalogResolver(CatalogCredential{Host: host, Port: port, User: "u", Password: "p"}))

	fn := e.objectIDFor("shop")
	if fn == nil {
		t.Fatal("expected a resolver function once orgID/catalog/database are all set")
	}
	if got := fn(context.Background(), 12345); got != "acme:postgres:shop:orders" {
		t.Fatalf("objectID = %q, want acme:postgres:shop:orders", got)
	}
	// tableOID 0 has no backing table: resolveObjectID is never even called for it by
	// parseRowDescription, but objectIDFor's own function must still degrade gracefully.
	if got := fn(context.Background(), 0); got != "" {
		t.Fatalf("tableOID 0 should resolve to empty ObjectID, got %q", got)
	}
}

// TestEngineProxy_VerbatimForwardsAndMasks drives Engine.Proxy end to end over net.Pipe: the client
// sends a plaintext StartupMessage, it is forwarded verbatim to "upstream" (never rewritten), and the
// upstream's result row comes back to the client with the configured masker applied.
func TestEngineProxy_VerbatimForwardsAndMasks(t *testing.T) {
	clientEnd, agentClient := net.Pipe()
	agentUpstream, upstreamEnd := net.Pipe()
	defer clientEnd.Close()
	defer agentUpstream.Close()
	deadline(t, clientEnd, agentClient, agentUpstream, upstreamEnd)

	engine := New()
	proxyErr := make(chan error, 1)
	go func() {
		proxyErr <- engine.Proxy(context.Background(), agentClient, agentUpstream,
			columnMasker{redact: map[string]bool{"email": true}}, wire.NoopRecorder{})
	}()

	// Client -> proxy -> upstream: verify the StartupMessage crosses byte-for-byte unmodified.
	startup := startupMessage(map[string]string{"user": "alice", "database": "appdb"})
	upErr := make(chan error, 1)
	go func() {
		got := make([]byte, len(startup))
		if _, err := io.ReadFull(upstreamEnd, got); err != nil {
			upErr <- err
			return
		}
		if !bytes.Equal(got, startup) {
			upErr <- errors.New("startup message was not forwarded verbatim")
			return
		}
		writeMsg(t, upstreamEnd, 'T', rowDescriptionPayload("id", "email"))
		writeMsg(t, upstreamEnd, 'D', dataRowPayload([]byte("1"), []byte("alice@example.com")))
		writeMsg(t, upstreamEnd, 'Z', []byte{'I'})
		upErr <- nil
	}()

	if _, err := clientEnd.Write(startup); err != nil {
		t.Fatalf("client write startup: %v", err)
	}

	cr := bufio.NewReader(clientEnd)
	var sawMasked, sawPlaintext bool
	for i := 0; i < 5; i++ {
		typ, payload, err := readBackendMessage(cr)
		if err != nil {
			break
		}
		if typ == 'D' {
			if strings.Contains(string(payload), "***") {
				sawMasked = true
			}
			if strings.Contains(string(payload), "alice@example.com") {
				sawPlaintext = true
			}
		}
		if typ == 'Z' {
			break
		}
	}
	if err := <-upErr; err != nil {
		t.Fatalf("upstream harness: %v", err)
	}
	if !sawMasked {
		t.Fatal("expected the email column masked in the verbatim proxy path")
	}
	if sawPlaintext {
		t.Fatal("plaintext email leaked through the verbatim proxy path")
	}
	_ = clientEnd.Close()
	_ = upstreamEnd.Close()
	<-proxyErr
}

// TestPipeBackendReader_ShortHeaderLength feeds a message header whose declared length is less than
// the 4-byte minimum (which must itself include the length field) — a malformed frame that carries
// no reliable way to know how many payload bytes to skip. Per the fallthrough-never-corrupt
// contract, a wire engine forwards what it *can* parse unmasked; here it cannot even determine frame
// boundaries, so aborting the connection (rather than guessing how many bytes to skip and
// desynchronizing the stream) is the correct, safe behavior.
func TestPipeBackendReader_ShortHeaderLength(t *testing.T) {
	server := new(bytes.Buffer)
	server.WriteByte('D')
	var l [4]byte
	binary.BigEndian.PutUint32(l[:], 2) // < 4: malformed, cannot possibly include itself
	server.Write(l[:])

	client := new(bytes.Buffer)
	err := pipeBackend(context.Background(), bytes.NewReader(server.Bytes()), client, mask.Noop{}, wire.NoopRecorder{}, nil)
	if !errors.Is(err, errProtocol) {
		t.Fatalf("expected errProtocol for an undersized message length, got %v", err)
	}
}

// TestPipeBackendReader_FlushesOnBufferDrain exercises the "flush whenever the read buffer is
// drained" branch (as opposed to only flushing at ReadyForQuery), by feeding a single non-'Z' message
// that leaves br.Buffered() == 0.
func TestPipeBackendReader_FlushesOnBufferDrain(t *testing.T) {
	server := new(bytes.Buffer)
	writeMsg(t, server, 'C', []byte("SELECT 1"))
	client := new(bytes.Buffer)
	err := pipeBackend(context.Background(), bytes.NewReader(server.Bytes()), client, mask.Noop{}, wire.NoopRecorder{}, nil)
	if err == nil || !errors.Is(err, io.EOF) {
		t.Fatalf("expected EOF at stream end, got %v", err)
	}
	if !bytes.Contains(client.Bytes(), []byte("SELECT 1")) {
		t.Fatal("expected the CommandComplete payload to have been flushed to the client")
	}
}

// TestParseRowDescription_EmptyPayload covers the len(p) < 2 guard: an implausibly short
// RowDescription payload is treated as "no columns" rather than panicking on the field-count read.
func TestParseRowDescription_EmptyPayload(t *testing.T) {
	if cols := parseRowDescription(context.Background(), []byte{0}, nil); cols != nil {
		t.Fatalf("expected nil for an undersized RowDescription payload, got %+v", cols)
	}
}

// TestParseRowDescription_TruncatedTrailerStopsWithoutCorrupting feeds a RowDescription payload that
// claims more columns than it actually has bytes for. Per fallthrough-never-corrupt, the parser must
// stop and return the columns it could parse rather than reading past the buffer or fabricating data.
func TestParseRowDescription_TruncatedTrailerStopsWithoutCorrupting(t *testing.T) {
	buf := new(bytes.Buffer)
	var u16 [2]byte
	binary.BigEndian.PutUint16(u16[:], 2) // claims 2 columns
	buf.Write(u16[:])
	buf.WriteString("id")
	buf.WriteByte(0)
	buf.Write(make([]byte, 10)) // far short of the 18-byte fixed trailer for column 1

	cols := parseRowDescription(context.Background(), buf.Bytes(), nil)
	if len(cols) != 0 {
		t.Fatalf("expected zero fully-parsed columns for a truncated trailer, got %d", len(cols))
	}
}

// TestParseRowDescription_MissingNameTerminator covers indexZero returning -1 (no NUL terminator
// found for a column name) — the parser must stop cleanly rather than run off the end of the slice.
func TestParseRowDescription_MissingNameTerminator(t *testing.T) {
	buf := new(bytes.Buffer)
	var u16 [2]byte
	binary.BigEndian.PutUint16(u16[:], 1)
	buf.Write(u16[:])
	buf.WriteString("unterminated") // no trailing NUL byte at all

	cols := parseRowDescription(context.Background(), buf.Bytes(), nil)
	if len(cols) != 0 {
		t.Fatalf("expected no columns when the name has no terminator, got %+v", cols)
	}
}

// TestMaskDataRow_TruncatedFieldLengthHeader covers the off+4 > len(p) guard (a DataRow payload that
// promises another field but is cut off before its 4-byte length prefix) — must error rather than
// read out of bounds.
func TestMaskDataRow_TruncatedFieldLengthHeader(t *testing.T) {
	buf := new(bytes.Buffer)
	var u16 [2]byte
	binary.BigEndian.PutUint16(u16[:], 1)
	buf.Write(u16[:])
	buf.Write([]byte{0, 0}) // only 2 of the 4 length bytes present

	_, _, err := maskDataRow(context.Background(), buf.Bytes(), nil, mask.Noop{})
	if !errors.Is(err, errProtocol) {
		t.Fatalf("expected errProtocol, got %v", err)
	}
}

// TestMaskDataRow_TruncatedFieldValue covers the off+int(flen) > len(p) guard: a field claims to be
// longer than the bytes actually remaining in the payload.
func TestMaskDataRow_TruncatedFieldValue(t *testing.T) {
	buf := new(bytes.Buffer)
	var u16 [2]byte
	binary.BigEndian.PutUint16(u16[:], 1)
	buf.Write(u16[:])
	var flen [4]byte
	binary.BigEndian.PutUint32(flen[:], 100) // claims 100 bytes
	buf.Write(flen[:])
	buf.WriteString("short") // far fewer than 100 bytes actually present

	_, _, err := maskDataRow(context.Background(), buf.Bytes(), nil, mask.Noop{})
	if !errors.Is(err, errProtocol) {
		t.Fatalf("expected errProtocol, got %v", err)
	}
}

// badLengthMasker returns a row with a different field count than it was given, simulating a masker
// bug/drift — maskDataRow must reject this rather than re-encode a corrupted row.
type badLengthMasker struct{}

func (badLengthMasker) MaskRow(_ context.Context, cols []mask.Column, row [][]byte) ([][]byte, error) {
	return row[:len(row)-1], nil
}

func TestMaskDataRow_MaskerReturnsWrongFieldCount(t *testing.T) {
	cols := parseRowDescription(context.Background(), rowDescriptionPayload("id", "email"), nil)
	payload := dataRowPayload([]byte("1"), []byte("a@b.com"))
	_, _, err := maskDataRow(context.Background(), payload, cols, badLengthMasker{})
	if !errors.Is(err, errProtocol) {
		t.Fatalf("expected errProtocol when the masker changes the field count, got %v", err)
	}
}

// TestWriteMessage_WriteFailurePropagates exercises both write-error branches of writeMessage: the
// header write and the payload write.
func TestWriteMessage_WriteFailurePropagates(t *testing.T) {
	if err := writeMessage(&failWriter{n: 0}, 'D', []byte("x")); err == nil {
		t.Fatal("expected an error when the header write fails")
	}
	if err := writeMessage(&failWriter{n: 5}, 'D', []byte("xyz")); err == nil {
		t.Fatal("expected an error when the payload write fails")
	}
}

// TestRenderRow_EmptyValues covers the len(values) == 0 short-circuit.
func TestRenderRow_EmptyValues(t *testing.T) {
	if got := renderRow(nil, nil); got != "" {
		t.Fatalf("renderRow(nil, nil) = %q, want empty", got)
	}
}

// TestRenderRow_FallsBackToPositionalName covers the "cols shorter than values" / empty-name
// fallback (colN) used on protocol drift, mirroring maskDataRow's "unknown column" handling.
func TestRenderRow_FallsBackToPositionalName(t *testing.T) {
	got := renderRow(nil, [][]byte{[]byte("7"), nil})
	if got != "col0=7, col1=NULL" {
		t.Fatalf("renderRow = %q", got)
	}
}

// TestNegotiateStartup_ClientDisconnectsDuringNegotiation covers negotiateStartup's read-error
// return path: if the client closes mid-negotiation frame, negotiateStartup must surface the error
// rather than block or panic.
func TestNegotiateStartup_ClientDisconnectsDuringNegotiation(t *testing.T) {
	clientEnd, serverEnd := net.Pipe()
	deadline(t, clientEnd, serverEnd)
	_ = clientEnd.Close() // closes before any bytes are sent

	_, _, err := negotiateStartup(serverEnd, nil)
	if err == nil {
		t.Fatal("expected an error when the client disconnects before sending a startup frame")
	}
	_ = serverEnd.Close()
}

func readFull(r *bufio.Reader, b []byte) (int, error) {
	got := 0
	for got < len(b) {
		n, err := r.Read(b[got:])
		got += n
		if err != nil {
			return got, err
		}
	}
	return got, nil
}
