package mysql

import (
	"bufio"
	"bytes"
	"context"
	"crypto/tls"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"testing"
	"time"

	"github.com/curlix-io/skybridge/internal/mask"
	"github.com/curlix-io/skybridge/internal/wire"
)

func TestName(t *testing.T) {
	if got := New().Name(); got != "mysql" {
		t.Fatalf("Name() = %q, want mysql", got)
	}
}

func TestWithOrgID_ScopesCopy(t *testing.T) {
	base := New()
	scoped := base.WithOrgID("org1")
	if base.orgID != "" {
		t.Fatal("WithOrgID must not mutate the receiver")
	}
	if scoped.orgID != "org1" {
		t.Fatalf("scoped.orgID = %q, want org1", scoped.orgID)
	}
}

func TestWithUpstreamTLS_ScopesCopy(t *testing.T) {
	base := New()
	cfg := &tls.Config{InsecureSkipVerify: true} //nolint:gosec // test
	scoped := base.WithUpstreamTLS(cfg, true)
	if base.upstreamTLS != nil {
		t.Fatal("WithUpstreamTLS must not mutate the receiver")
	}
	if scoped.upstreamTLS != cfg || !scoped.upstreamRequired {
		t.Fatal("expected the copy to carry the TLS config and required flag")
	}
}

// ---- passthrough ----

func TestPassthrough_CopiesBothDirections(t *testing.T) {
	clientConn, engineClient := net.Pipe()
	upstreamListenerConn, engineUpstream := net.Pipe()
	defer clientConn.Close()
	defer upstreamListenerConn.Close()

	done := make(chan error, 1)
	go func() {
		done <- passthrough(bufio.NewReader(engineClient), bufio.NewReader(engineUpstream), engineClient, engineUpstream)
	}()

	go func() { _, _ = clientConn.Write([]byte("hello-upstream")) }()
	buf := make([]byte, len("hello-upstream"))
	if _, err := io.ReadFull(upstreamListenerConn, buf); err != nil {
		t.Fatalf("upstream did not receive client bytes: %v", err)
	}
	if string(buf) != "hello-upstream" {
		t.Fatalf("got %q", buf)
	}

	go func() { _, _ = upstreamListenerConn.Write([]byte("hello-client")) }()
	buf2 := make([]byte, len("hello-client"))
	if _, err := io.ReadFull(clientConn, buf2); err != nil {
		t.Fatalf("client did not receive upstream bytes: %v", err)
	}
	if string(buf2) != "hello-client" {
		t.Fatalf("got %q", buf2)
	}

	_ = clientConn.Close()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("passthrough did not return after connections closed")
	}
}

// ---- Proxy: client-TLS drops to passthrough ----

func TestProxy_ClientSSLDropsToPassthrough(t *testing.T) {
	clientConn, engineClient := net.Pipe()
	engineUpstream, upstreamConn := net.Pipe()
	defer clientConn.Close()
	defer engineUpstream.Close()
	dl := time.Now().Add(5 * time.Second)
	for _, c := range []net.Conn{clientConn, engineClient, engineUpstream, upstreamConn} {
		_ = c.SetDeadline(dl)
	}

	engine := New()
	proxyErr := make(chan error, 1)
	go func() {
		proxyErr <- engine.Proxy(context.Background(), engineClient, engineUpstream, mask.Noop{}, wire.NoopRecorder{})
	}()

	go func() { _, _ = upstreamConn.Write(pkt(0, buildGreeting(capClientProtocol41))) }()

	cr := bufio.NewReader(clientConn)
	if _, _, _, err := readPacket(cr); err != nil {
		t.Fatalf("client read greeting: %v", err)
	}
	// HandshakeResponse advertising CLIENT_SSL: the engine cannot parse further and drops to
	// transparent passthrough.
	resp := make([]byte, 40)
	binary.LittleEndian.PutUint32(resp[0:4], capClientSSL|capClientProtocol41)
	if _, err := clientConn.Write(pkt(1, resp)); err != nil {
		t.Fatalf("client send SSL handshake response: %v", err)
	}
	// Upstream must receive the SSL handshake response verbatim.
	ur := bufio.NewReader(upstreamConn)
	useq, upayload, _, err := readPacket(ur)
	if err != nil {
		t.Fatalf("upstream read handshake response: %v", err)
	}
	if useq != 1 || !bytes.Equal(upayload, resp) {
		t.Fatal("expected the SSL handshake response forwarded verbatim to upstream")
	}
	// Passthrough is now transparent: bytes sent by upstream reach the client raw.
	if _, err := upstreamConn.Write([]byte("raw-bytes")); err != nil {
		t.Fatalf("upstream write: %v", err)
	}
	buf := make([]byte, len("raw-bytes"))
	if _, err := io.ReadFull(clientConn, buf); err != nil {
		t.Fatalf("client did not receive passthrough bytes: %v", err)
	}
	if string(buf) != "raw-bytes" {
		t.Fatalf("got %q", buf)
	}
	_ = clientConn.Close()
	select {
	case <-proxyErr:
	case <-time.After(5 * time.Second):
		t.Fatal("Proxy did not return")
	}
}

// ---- forwardRest ----

func TestForwardRest_CopiesRemainingBytes(t *testing.T) {
	src := bufio.NewReader(bytes.NewReader([]byte("remaining-bytes")))
	var out bytes.Buffer
	bw := bufio.NewWriter(&out)
	if err := forwardRest(src, bw); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if out.String() != "remaining-bytes" {
		t.Fatalf("got %q", out.String())
	}
}

// ---- resultStatus ----

func TestResultStatus_EOFVariant(t *testing.T) {
	// EOF packet: header(1) warnings(2) status(2)
	p := []byte{pktEOF, 0, 0, 0x08, 0x00} // status = statusMoreResults
	if got := resultStatus(p, false); got != statusMoreResults {
		t.Fatalf("resultStatus = %#x, want %#x", got, statusMoreResults)
	}
}

func TestResultStatus_EOFTooShort(t *testing.T) {
	p := []byte{pktEOF, 0, 0}
	if got := resultStatus(p, false); got != 0 {
		t.Fatalf("resultStatus = %#x, want 0", got)
	}
}

func TestResultStatus_OKVariant(t *testing.T) {
	var p []byte
	p = append(p, pktEOF)      // OK header re-uses pktOK==0x00 value space; deprecateEOF path checks p[0]==pktEOF
	p = appendLenEncInt(p, 5)  // affected rows
	p = appendLenEncInt(p, 10) // last insert id
	p = append(p, 0x08, 0x00)  // status
	if got := resultStatus(p, true); got != statusMoreResults {
		t.Fatalf("resultStatus (OK variant) = %#x, want %#x", got, statusMoreResults)
	}
}

func TestResultStatus_OKTruncatedAffectedRows(t *testing.T) {
	p := []byte{pktEOF, 0xFE} // 0xFE lenenc prefix needs 8 more bytes, none present
	if got := resultStatus(p, true); got != 0 {
		t.Fatalf("resultStatus = %#x, want 0", got)
	}
}

func TestResultStatus_OKTruncatedLastInsertID(t *testing.T) {
	var p []byte
	p = append(p, pktEOF)
	p = appendLenEncInt(p, 1)
	p = append(p, 0xFE) // truncated lenenc for last_insert_id
	if got := resultStatus(p, true); got != 0 {
		t.Fatalf("resultStatus = %#x, want 0", got)
	}
}

func TestResultStatus_OKMissingStatusBytes(t *testing.T) {
	var p []byte
	p = append(p, pktEOF)
	p = appendLenEncInt(p, 1)
	p = appendLenEncInt(p, 1)
	// no trailing status bytes
	if got := resultStatus(p, true); got != 0 {
		t.Fatalf("resultStatus = %#x, want 0", got)
	}
}

func TestResultStatus_NotEOF(t *testing.T) {
	if got := resultStatus([]byte{0x01, 0x02}, false); got != 0 {
		t.Fatalf("resultStatus = %#x, want 0 for a non-EOF packet", got)
	}
	if got := resultStatus(nil, false); got != 0 {
		t.Fatalf("resultStatus(nil) = %#x, want 0", got)
	}
}

// ---- handleOneResultSet / handleResultResponse additional branches ----

func TestServerToClient_MultiStatementMoreResults(t *testing.T) {
	s := &state{caps: 0, queries: make(chan struct{}, 1)}
	s.queries <- struct{}{}

	var stream bytes.Buffer
	// First result set: 1 col, EOF, one row, EOF with SERVER_MORE_RESULTS_EXISTS set.
	stream.Write(pkt(1, []byte{0x01}))
	stream.Write(pkt(2, colDef("email")))
	stream.Write(pkt(3, eofPacket()))
	stream.Write(pkt(4, textRow("alice@example.com")))
	stream.Write(pkt(5, []byte{pktEOF, 0x00, 0x00, 0x08, 0x00})) // status has SERVER_MORE_RESULTS_EXISTS
	// Second result set: 1 col, EOF, one row, terminating EOF (no more results).
	stream.Write(pkt(6, []byte{0x01}))
	stream.Write(pkt(7, colDef("name")))
	stream.Write(pkt(8, eofPacket()))
	stream.Write(pkt(9, textRow("Bob")))
	stream.Write(pkt(10, eofPacket()))

	overlay := mask.NewOverlay(map[string]string{"email": "[redacted]"})
	var out bytes.Buffer
	sb := bufio.NewReader(&stream)
	err := s.serverToClient(context.Background(), sb, &out, overlay, wire.NoopRecorder{})
	if err != io.EOF && err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	got := out.Bytes()
	if bytes.Contains(got, []byte("alice@example.com")) {
		t.Fatal("email from first result set leaked")
	}
	if !bytes.Contains(got, []byte("Bob")) {
		t.Fatal("second result set's row lost")
	}
}

func TestServerToClient_ColumnCountParseFailureForwardsRaw(t *testing.T) {
	s := &state{caps: 0, queries: make(chan struct{}, 1)}
	s.queries <- struct{}{}

	var stream bytes.Buffer
	// 0xFB is not a valid lenenc length prefix in this context -> readLenEncInt fails.
	stream.Write(pkt(1, []byte{0xFB}))

	var out bytes.Buffer
	sb := bufio.NewReader(&stream)
	_ = s.serverToClient(context.Background(), sb, &out, mask.Noop{}, wire.NoopRecorder{})
	if !bytes.Equal(out.Bytes(), pkt(1, []byte{0xFB})) {
		t.Fatalf("expected the unparseable packet forwarded raw, got %v", out.Bytes())
	}
}

// capturingMasker records the mask.Column slice it was called with, for asserting what identity a
// caller actually resolved (as opposed to what MaskRow does with it).
type capturingMasker struct {
	captured []mask.Column
}

func (m *capturingMasker) MaskRow(_ context.Context, cols []mask.Column, row [][]byte) ([][]byte, error) {
	m.captured = append([]mask.Column(nil), cols...)
	return row, nil
}

// TestServerToClient_ResolvesRealColumnNameForAliasedColumn is the regression test for
// docs/PATH_LABEL_IDENTITY_GAPS_DESIGN.md's Gap A at the wire-engine level (see mysql_test.go's
// TestColumnIdentityResolvesRealNameForAliasedColumn for the columnIdentity-level unit test): a
// result set for "SELECT email AS contact_info FROM users" must still set mask.Column.Path to the
// real column name "email" (org_name), not the aliased display name "contact_info" (name) —
// otherwise a path-scoped label confirmed on "email" can never match this row.
func TestServerToClient_ResolvesRealColumnNameForAliasedColumn(t *testing.T) {
	s := &state{caps: 0, queries: make(chan struct{}, 1), orgID: "org1"}
	s.queries <- struct{}{}

	var stream bytes.Buffer
	stream.Write(pkt(1, []byte{0x01}))
	stream.Write(pkt(2, colDefAliased("contact_info", "email", 0xFD)))
	stream.Write(pkt(3, eofPacket()))
	stream.Write(pkt(4, textRow("alice@example.com")))
	stream.Write(pkt(5, eofPacket()))

	masker := &capturingMasker{}
	var out bytes.Buffer
	sb := bufio.NewReader(&stream)
	_ = s.serverToClient(context.Background(), sb, &out, masker, wire.NoopRecorder{})

	if len(masker.captured) != 1 {
		t.Fatalf("expected exactly 1 captured column, got %d", len(masker.captured))
	}
	col := masker.captured[0]
	if col.Name != "contact_info" {
		t.Fatalf("Name = %q, want the aliased display name %q", col.Name, "contact_info")
	}
	if col.Path != "email" {
		t.Fatalf("Path = %q, want the real column name %q (a path-scoped label lookup keys on Path)", col.Path, "email")
	}
	if col.ObjectID != "org1:mysql:test:t" {
		t.Fatalf("ObjectID = %q, want org1:mysql:test:t", col.ObjectID)
	}
}

func TestServerToClient_FullColumnDefFallsBackToRawForward(t *testing.T) {
	s := &state{caps: 0, queries: make(chan struct{}, 1)}
	s.queries <- struct{}{}

	var stream bytes.Buffer
	stream.Write(pkt(1, []byte{0x01})) // 1 column
	// A "full" (0xFFFFFF byte) column-def packet signals a multi-packet logical packet we don't
	// reassemble; the engine must fall back to raw forwarding of the rest of the stream.
	full := make([]byte, maxPacket)
	stream.Write(pkt(2, full))
	stream.Write([]byte("trailing-bytes-after-full-packet"))

	var out bytes.Buffer
	sb := bufio.NewReader(&stream)
	_ = s.serverToClient(context.Background(), sb, &out, mask.Noop{}, wire.NoopRecorder{})
	if !bytes.Contains(out.Bytes(), []byte("trailing-bytes-after-full-packet")) {
		t.Fatal("expected the remaining stream forwarded raw after a full packet")
	}
}

func TestServerToClient_FullRowPacketFallsBackToRawForward(t *testing.T) {
	s := &state{caps: 0, queries: make(chan struct{}, 1)}
	s.queries <- struct{}{}

	var stream bytes.Buffer
	stream.Write(pkt(1, []byte{0x01}))
	stream.Write(pkt(2, colDef("email")))
	stream.Write(pkt(3, eofPacket()))
	full := make([]byte, maxPacket)
	stream.Write(pkt(4, full))
	stream.Write([]byte("trailing-row-bytes"))

	var out bytes.Buffer
	sb := bufio.NewReader(&stream)
	_ = s.serverToClient(context.Background(), sb, &out, mask.Noop{}, wire.NoopRecorder{})
	if !bytes.Contains(out.Bytes(), []byte("trailing-row-bytes")) {
		t.Fatal("expected the remaining stream forwarded raw after a full row packet")
	}
}

func TestServerToClient_DeprecateEOFSkipsColumnEOF(t *testing.T) {
	s := &state{caps: capClientDeprecateEOF, queries: make(chan struct{}, 1)}
	s.queries <- struct{}{}

	var stream bytes.Buffer
	stream.Write(pkt(1, []byte{0x01}))
	stream.Write(pkt(2, colDef("email")))
	// No EOF after column defs (DEPRECATE_EOF negotiated).
	stream.Write(pkt(3, textRow("alice@example.com")))
	// Terminating OK packet (DEPRECATE_EOF uses OK, not EOF, but isTerminator checks p[0]==pktEOF
	// regardless; use an EOF-shaped terminator per protocol for DEPRECATE_EOF, len>=9 marks it as OK-EOF).
	term := append([]byte{pktEOF}, make([]byte, 8)...)
	stream.Write(pkt(4, term))

	overlay := mask.NewOverlay(map[string]string{"email": "[redacted]"})
	var out bytes.Buffer
	sb := bufio.NewReader(&stream)
	_ = s.serverToClient(context.Background(), sb, &out, overlay, wire.NoopRecorder{})
	got := out.Bytes()
	if bytes.Contains(got, []byte("alice@example.com")) {
		t.Fatal("email leaked in DEPRECATE_EOF result set")
	}
	if !bytes.Contains(got, []byte("[redacted]")) {
		t.Fatal("expected masking to apply under DEPRECATE_EOF")
	}
}

func TestServerToClient_RowTooLargeAfterMaskingForwardsOriginal(t *testing.T) {
	// A masker that inflates a value beyond maxPacket must not have its output used (the ok branch
	// requires len(newPayload) < maxPacket); the original row packet is forwarded unchanged.
	s := &state{caps: 0, queries: make(chan struct{}, 1)}
	s.queries <- struct{}{}

	var stream bytes.Buffer
	stream.Write(pkt(1, []byte{0x01}))
	stream.Write(pkt(2, colDef("email")))
	stream.Write(pkt(3, eofPacket()))
	stream.Write(pkt(4, textRow("alice@example.com")))
	stream.Write(pkt(5, eofPacket()))

	huge := &hugeValueMasker{}
	var out bytes.Buffer
	sb := bufio.NewReader(&stream)
	_ = s.serverToClient(context.Background(), sb, &out, huge, wire.NoopRecorder{})
	// The row bytes as sent to the client should be the original (small) row, not a huge one.
	got := out.Bytes()
	if bytes.Contains(got, []byte("alice@example.com")) {
		// ok: this masker doesn't leave the original value, it replaces with a huge value that gets
		// rejected — so the ORIGINAL unmodified payload (still containing the email) is forwarded.
		// That's the documented, safe-by-construction behavior: fall back rather than corrupt.
		return
	}
	t.Fatal("expected the original row (with the email) forwarded when the masked value is too large")
}

type hugeValueMasker struct{}

func (hugeValueMasker) MaskRow(_ context.Context, _ []mask.Column, row [][]byte) ([][]byte, error) {
	out := make([][]byte, len(row))
	for i := range row {
		out[i] = bytes.Repeat([]byte("x"), maxPacket+1)
	}
	return out, nil
}

// ---- lenEncStrSpan / lenEncStr truncation ----

func TestLenEncStrSpan_Truncated(t *testing.T) {
	if _, ok := lenEncStrSpan([]byte{0xFC, 0x01}, 0); ok {
		t.Fatal("expected truncated lenenc int to fail")
	}
	// valid length prefix but not enough bytes for the string body.
	p := appendLenEncInt(nil, 10)
	if _, ok := lenEncStrSpan(p, 0); ok {
		t.Fatal("expected span to fail when declared length exceeds available bytes")
	}
}

func TestLenEncStr_Truncated(t *testing.T) {
	if got := lenEncStr([]byte{0xFC, 0x01}, 0); got != "" {
		t.Fatalf("expected empty string, got %q", got)
	}
	p := appendLenEncInt(nil, 10)
	if got := lenEncStr(p, 0); got != "" {
		t.Fatalf("expected empty string when body is short, got %q", got)
	}
}

// ---- columnIdentity additional truncation branches ----

func TestColumnIdentity_TruncatedCatalogSpan(t *testing.T) {
	name, schema, orgTable, orgName, freeText := columnIdentity([]byte{0xFC, 0x01})
	if name != "" || schema != "" || orgTable != "" || orgName != "" || !freeText {
		t.Fatalf("expected empty identity + freeText=true fallback, got (%q,%q,%q,%q,%v)", name, schema, orgTable, orgName, freeText)
	}
}

func TestColumnIdentity_TruncatedAfterOrgTableBeforeNameLen(t *testing.T) {
	var p []byte
	lenStr := func(s string) {
		p = appendLenEncInt(p, uint64(len(s)))
		p = append(p, s...)
	}
	lenStr("def")
	lenStr("test")
	lenStr("t")
	lenStr("t")
	// truncate here: no name-length lenenc int follows
	name, schema, orgTable, orgName, freeText := columnIdentity(p)
	if name != "" || orgName != "" || !freeText {
		t.Fatalf("expected empty name + freeText=true fallback, got (%q,%q,%q,%q,%v)", name, schema, orgTable, orgName, freeText)
	}
}

func TestColumnIdentity_TruncatedNameBody(t *testing.T) {
	var p []byte
	lenStr := func(s string) {
		p = appendLenEncInt(p, uint64(len(s)))
		p = append(p, s...)
	}
	lenStr("def")
	lenStr("test")
	lenStr("t")
	lenStr("t")
	p = appendLenEncInt(p, 100) // name length claims 100 bytes, none follow
	name, schema, orgTable, orgName, freeText := columnIdentity(p)
	if name != "" || orgName != "" || !freeText {
		t.Fatalf("expected empty name + freeText=true fallback, got (%q,%q,%q,%q,%v)", name, schema, orgTable, orgName, freeText)
	}
}

func TestColumnIdentity_MissingOrgNameSpanReturnsFreeText(t *testing.T) {
	var p []byte
	lenStr := func(s string) {
		p = appendLenEncInt(p, uint64(len(s)))
		p = append(p, s...)
	}
	lenStr("def")
	lenStr("test")
	lenStr("t")
	lenStr("t")
	lenStr("email")
	// no org_name follows
	name, schema, orgTable, orgName, freeText := columnIdentity(p)
	if name != "email" || schema != "test" || orgTable != "t" || orgName != "email" || !freeText {
		t.Fatalf("got (%q,%q,%q,%q,%v)", name, schema, orgTable, orgName, freeText)
	}
}

func TestColumnIdentity_MissingFixedFieldsLenReturnsFreeText(t *testing.T) {
	var p []byte
	lenStr := func(s string) {
		p = appendLenEncInt(p, uint64(len(s)))
		p = append(p, s...)
	}
	lenStr("def")
	lenStr("test")
	lenStr("t")
	lenStr("t")
	lenStr("email")
	lenStr("email")
	// no length_of_fixed_fields lenenc follows
	name, schema, orgTable, orgName, freeText := columnIdentity(p)
	if name != "email" || orgName != "email" || !freeText {
		t.Fatalf("got (%q,%q,%q,%q,%v)", name, schema, orgTable, orgName, freeText)
	}
}

func TestColumnIdentity_TypeByteMissingReturnsFreeText(t *testing.T) {
	var p []byte
	lenStr := func(s string) {
		p = appendLenEncInt(p, uint64(len(s)))
		p = append(p, s...)
	}
	lenStr("def")
	lenStr("test")
	lenStr("t")
	lenStr("t")
	lenStr("email")
	lenStr("email")
	p = append(p, 0x0c)
	p = append(p, 0x21, 0x00)
	p = append(p, 0x00, 0x01, 0x00, 0x00)
	// stop right before the type byte
	name, _, _, _, freeText := columnIdentity(p)
	if name != "email" || !freeText {
		t.Fatalf("expected freeText=true when type byte is missing, got name=%q freeText=%v", name, freeText)
	}
}

// ---- errors.Is sanity for readLenEncInt already covered elsewhere; test writePacket error path ----

func TestWritePacket_PropagatesWriteError(t *testing.T) {
	if err := writePacket(failWriter{}, 0, []byte("x")); err == nil {
		t.Fatal("expected the underlying write error to propagate")
	}
}

type failWriter struct{}

func (failWriter) Write([]byte) (int, error) { return 0, errors.New("boom") }

// ---- readPacket error propagation on header/body read failure already covered by other tests via
// EOF; add a case for a payload read failure distinct from header failure.

func TestReadPacket_HeaderReadError(t *testing.T) {
	r := bufio.NewReader(bytes.NewReader([]byte{1, 2})) // too short for a 4-byte header
	if _, _, _, err := readPacket(r); err == nil {
		t.Fatal("expected an error for a truncated packet header")
	}
}

func TestReadPacket_PayloadReadError(t *testing.T) {
	hdr := []byte{5, 0, 0, 0}                                // declares 5 payload bytes
	r := bufio.NewReader(bytes.NewReader(append(hdr, 1, 2))) // only 2 provided
	if _, _, _, err := readPacket(r); err == nil {
		t.Fatal("expected an error for a truncated packet payload")
	}
}

// ---- renderTextRow ----

func TestRenderTextRow_Empty(t *testing.T) {
	if got := renderTextRow(nil, nil); got != "" {
		t.Fatalf("got %q, want empty", got)
	}
}

func TestRenderTextRow_MissingColumnNameFallsBackToIndex(t *testing.T) {
	got := renderTextRow(nil, [][]byte{[]byte("v0"), nil})
	if got != "col0=v0, col1=NULL" {
		t.Fatalf("got %q", got)
	}
}
