package mongo

import (
	"bufio"
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"net"
	"testing"
	"time"

	"github.com/curlix-io/skybridge/internal/mask"
	"github.com/curlix-io/skybridge/internal/wire"
)

func TestNew_DefaultsUnscoped(t *testing.T) {
	e := New()
	if e == nil {
		t.Fatal("New returned nil")
	}
	if e.orgID != "" {
		t.Fatalf("expected unscoped orgID, got %q", e.orgID)
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

func TestName(t *testing.T) {
	if got := New().Name(); got != "mongodb" {
		t.Fatalf("Name() = %q, want mongodb", got)
	}
}

// TestProxy_EndToEndMasksAndForwards drives Engine.Proxy over net.Pipe: the client sends a find
// command, the fake upstream server replies with a batch, and the client must see the masked
// reply while the request reaches the upstream verbatim.
func TestProxy_EndToEndMasksAndForwards(t *testing.T) {
	clientConn, engineClient := net.Pipe()
	engineUpstream, upstreamConn := net.Pipe()
	defer clientConn.Close()
	defer engineUpstream.Close()
	dl := time.Now().Add(8 * time.Second)
	for _, c := range []net.Conn{clientConn, engineClient, engineUpstream, upstreamConn} {
		_ = c.SetDeadline(dl)
	}

	engine := New().WithOrgID("org1")
	overlay := mask.NewOverlay(map[string]string{"email": "[redacted]"})

	proxyErr := make(chan error, 1)
	go func() {
		proxyErr <- engine.Proxy(context.Background(), engineClient, engineUpstream, overlay, wire.NoopRecorder{})
	}()

	upstreamDone := make(chan error, 1)
	go func() {
		br := bufio.NewReader(upstreamConn)
		msg, err := readMessage(br)
		if err != nil {
			upstreamDone <- err
			return
		}
		requestID := int32(binary.LittleEndian.Uint32(msg[4:8]))
		reply := opMsgReplyTo(findReplyBody(), requestID)
		if _, err := upstreamConn.Write(reply); err != nil {
			upstreamDone <- err
			return
		}
		upstreamDone <- nil
	}()

	req := opMsgRequest(findCommand("orders", "shop"), 99)
	if _, err := clientConn.Write(req); err != nil {
		t.Fatalf("client write request: %v", err)
	}

	cr := bufio.NewReader(clientConn)
	out, err := readMessage(cr)
	if err != nil {
		t.Fatalf("client read reply: %v", err)
	}
	if bytes.Contains(out, []byte("alice@example.com")) {
		t.Fatal("email leaked through Proxy")
	}
	if !bytes.Contains(out, []byte("[redacted]")) {
		t.Fatal("masking not applied through Proxy")
	}

	if err := <-upstreamDone; err != nil {
		t.Fatalf("upstream harness: %v", err)
	}
	_ = clientConn.Close()
	select {
	case <-proxyErr:
	case <-time.After(5 * time.Second):
		t.Fatal("Proxy did not return after client closed")
	}
}

// TestProxyClientRequests_ForwardsAndTracksAndErrors exercises proxyClientRequests directly:
// verbatim forwarding, recorder input, tracker observation, and propagating a read error.
func TestProxyClientRequests_ForwardsAndTracksAndErrors(t *testing.T) {
	req := opMsgRequest(findCommand("orders", "shop"), 5)
	r := bufio.NewReader(bytes.NewReader(req))
	var out bytes.Buffer
	rec := &captureRecorder{}
	tr := newRequestTracker()

	err := proxyClientRequests(r, &out, rec, tr)
	if err == nil {
		t.Fatal("expected an EOF-class error once the input is exhausted")
	}
	if !bytes.Equal(out.Bytes(), req) {
		t.Fatal("request bytes must be forwarded verbatim")
	}
	if len(rec.inputs) != 1 {
		t.Fatalf("expected 1 recorded input, got %d", len(rec.inputs))
	}
	if info, ok := tr.resolve(5); !ok || info.collection != "orders" {
		t.Fatalf("expected tracker to observe requestID 5, got %+v %v", info, ok)
	}
}

type captureRecorder struct {
	inputs  [][]byte
	outputs []string
}

func (c *captureRecorder) RecordInput(raw []byte) {
	c.inputs = append(c.inputs, append([]byte(nil), raw...))
}
func (c *captureRecorder) RecordOutput(text string) { c.outputs = append(c.outputs, text) }

// ---- readMessage ----

func TestReadMessage_ImplausibleLengthTooSmall(t *testing.T) {
	var hdr [4]byte
	binary.LittleEndian.PutUint32(hdr[:], 4) // less than headerLen(16)
	r := bufio.NewReader(bytes.NewReader(hdr[:]))
	if _, err := readMessage(r); err == nil {
		t.Fatal("expected an error for an implausibly small message length")
	}
}

func TestReadMessage_ImplausibleLengthTooLarge(t *testing.T) {
	var hdr [4]byte
	binary.LittleEndian.PutUint32(hdr[:], maxMessageBytes+1)
	r := bufio.NewReader(bytes.NewReader(hdr[:]))
	if _, err := readMessage(r); err == nil {
		t.Fatal("expected an error for an implausibly large message length")
	}
}

func TestReadMessage_TruncatedBody(t *testing.T) {
	var hdr [4]byte
	binary.LittleEndian.PutUint32(hdr[:], 20)
	r := bufio.NewReader(bytes.NewReader(hdr[:])) // no body bytes follow
	if _, err := readMessage(r); err == nil {
		t.Fatal("expected an error when the body is truncated")
	}
}

func TestReadMessage_RoundTrip(t *testing.T) {
	msg := opMsgReply(findReplyBody())
	r := bufio.NewReader(bytes.NewReader(msg))
	got, err := readMessage(r)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !bytes.Equal(got, msg) {
		t.Fatal("readMessage must return the message byte-identical")
	}
}

// ---- sequence (OP_MSG document-sequence section) ----

// opMsgWithSequence builds an OP_MSG whose only section is a kind-1 document sequence containing
// docs, identified by identifier.
func opMsgWithSequence(identifier string, docs ...[]byte) []byte {
	var sec []byte
	sec = append(sec, 0, 0, 0, 0) // size placeholder
	sec = append(sec, identifier...)
	sec = append(sec, 0)
	for _, d := range docs {
		sec = append(sec, d...)
	}
	binary.LittleEndian.PutUint32(sec[0:4], uint32(len(sec)))

	msg := make([]byte, 20)
	binary.LittleEndian.PutUint32(msg[12:16], opMsg)
	msg = append(msg, 1) // section kind 1 (document sequence)
	msg = append(msg, sec...)
	binary.LittleEndian.PutUint32(msg[0:4], uint32(len(msg)))
	return msg
}

func TestTransformMessage_DocumentSequenceMasked(t *testing.T) {
	doc := bdoc(estring("email", "seq@example.com"))
	msg := opMsgWithSequence("documents", doc)

	bm := &bsonMasker{ctx: context.Background(), masker: mask.NewOverlay(map[string]string{"email": "[redacted]"})}
	out, err := transformMessage(bm, msg)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if bytes.Contains(out, []byte("seq@example.com")) {
		t.Fatal("document-sequence section email not masked")
	}
	if !bytes.Contains(out, []byte("[redacted]")) {
		t.Fatal("expected redaction in document-sequence section")
	}
	if !bytes.Contains(out, []byte("documents")) {
		t.Fatal("sequence identifier lost")
	}
}

func TestTransformMessage_DocumentSequenceMaskerError(t *testing.T) {
	doc := bdoc(estring("email", "seq@example.com"))
	msg := opMsgWithSequence("documents", doc)

	bm := &bsonMasker{ctx: context.Background(), masker: errMasker{}}
	_, err := transformMessage(bm, msg)
	if !errors.Is(err, mask.ErrMaskerUnavailable) {
		t.Fatalf("expected ErrMaskerUnavailable, got %v", err)
	}
}

func TestTransformMessage_UnknownSectionKindPassthrough(t *testing.T) {
	msg := make([]byte, 20)
	binary.LittleEndian.PutUint32(msg[12:16], opMsg)
	msg = append(msg, 2) // invalid section kind
	binary.LittleEndian.PutUint32(msg[0:4], uint32(len(msg)))

	bm := &bsonMasker{ctx: context.Background(), masker: mask.NewOverlay(map[string]string{"email": "x"})}
	out, err := transformMessage(bm, msg)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !bytes.Equal(out, msg) {
		t.Fatal("unknown section kind must pass through unchanged")
	}
}

func TestSequence_MalformedTooShort(t *testing.T) {
	bm := &bsonMasker{ctx: context.Background(), masker: mask.Noop{}}
	if _, _, err := bm.sequence([]byte{1, 2, 3}); err == nil {
		t.Fatal("expected an error for a too-short sequence section")
	}
}

func TestSequence_MissingIdentifierTerminator(t *testing.T) {
	bm := &bsonMasker{ctx: context.Background(), masker: mask.Noop{}}
	sec := []byte{0, 0, 0, 0, 'a', 'b'} // no NUL terminator for the identifier
	if _, _, err := bm.sequence(sec); err == nil {
		t.Fatal("expected an error when the identifier cstring is unterminated")
	}
}

func TestSequence_TruncatedDocLength(t *testing.T) {
	bm := &bsonMasker{ctx: context.Background(), masker: mask.Noop{}}
	var sec []byte
	sec = append(sec, 0, 0, 0, 0)
	sec = append(sec, "id"...)
	sec = append(sec, 0)
	sec = append(sec, 1, 2) // not enough bytes for a doc length prefix
	binary.LittleEndian.PutUint32(sec[0:4], uint32(len(sec)))
	if _, _, err := bm.sequence(sec); err == nil {
		t.Fatal("expected an error for a truncated document length")
	}
}

func TestSequence_DocLengthOverflows(t *testing.T) {
	bm := &bsonMasker{ctx: context.Background(), masker: mask.Noop{}}
	var sec []byte
	sec = append(sec, 0, 0, 0, 0)
	sec = append(sec, "id"...)
	sec = append(sec, 0)
	// A document length that claims more bytes than actually follow.
	var dl [4]byte
	binary.LittleEndian.PutUint32(dl[:], 100)
	sec = append(sec, dl[:]...)
	binary.LittleEndian.PutUint32(sec[0:4], uint32(len(sec)))
	if _, _, err := bm.sequence(sec); err == nil {
		t.Fatal("expected an error when the declared doc length overflows the section")
	}
}

func TestSequence_NoChangeWhenNothingMasked(t *testing.T) {
	doc := bdoc(estring("name", "Alice")) // no PII field matched by the overlay
	msg := opMsgWithSequence("documents", doc)
	bm := &bsonMasker{ctx: context.Background(), masker: mask.NewOverlay(map[string]string{"email": "[redacted]"})}
	out, err := transformMessage(bm, msg)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !bytes.Equal(out, msg) {
		t.Fatal("expected the message unchanged when no field was masked")
	}
}

// ---- indexByte ----

func TestIndexByte(t *testing.T) {
	if got := indexByte([]byte{1, 2, 0, 3}); got != 2 {
		t.Fatalf("indexByte = %d, want 2", got)
	}
	if got := indexByte([]byte{1, 2, 3}); got != -1 {
		t.Fatalf("indexByte = %d, want -1", got)
	}
}

// ---- valueLen additional types ----

func TestValueLen_AdditionalTypes(t *testing.T) {
	if n, err := valueLen(bsonDouble, make([]byte, 8)); err != nil || n != 8 {
		t.Fatalf("double: %d %v", n, err)
	}
	if n, err := valueLen(bsonBool, []byte{1}); err != nil || n != 1 {
		t.Fatalf("bool: %d %v", n, err)
	}
	if n, err := valueLen(bsonNull, nil); err != nil || n != 0 {
		t.Fatalf("null: %d %v", n, err)
	}
	if n, err := valueLen(bsonDecimal, make([]byte, 16)); err != nil || n != 16 {
		t.Fatalf("decimal: %d %v", n, err)
	}
	// binary: 4-byte length + 1 subtype + payload
	bin := append([]byte{3, 0, 0, 0}, []byte{0x00, 'a', 'b', 'c'}...)
	if n, err := valueLen(bsonBinary, bin); err != nil || n != 8 {
		t.Fatalf("binary: %d %v", n, err)
	}
	if _, err := valueLen(bsonBinary, []byte{1, 2}); err == nil {
		t.Fatal("expected error for truncated binary length")
	}
	// doc/array: length prefix must be >= 5
	shortDoc := []byte{4, 0, 0, 0}
	if _, err := valueLen(bsonDoc, shortDoc); err == nil {
		t.Fatal("expected error for a doc length < 5")
	}
	validDoc := bdoc()
	if n, err := valueLen(bsonDoc, validDoc); err != nil || n != len(validDoc) {
		t.Fatalf("doc: %d %v, want %d", n, err, len(validDoc))
	}
	// dbpointer: 4-byte length + bytes + 12
	dbp := append([]byte{2, 0, 0, 0}, []byte("ab")...)
	dbp = append(dbp, make([]byte, 12)...)
	if n, err := valueLen(bsonDBPointer, dbp); err != nil || n != 4+2+12 {
		t.Fatalf("dbpointer: %d %v", n, err)
	}
	if _, err := valueLen(bsonDBPointer, []byte{1}); err == nil {
		t.Fatal("expected error for truncated dbpointer length")
	}
	// regex: pattern NUL options NUL
	regex := append([]byte("pat"), 0)
	regex = append(regex, []byte("i")...)
	regex = append(regex, 0)
	if n, err := valueLen(bsonRegex, regex); err != nil || n != len(regex) {
		t.Fatalf("regex: %d %v, want %d", n, err, len(regex))
	}
	if _, err := valueLen(bsonRegex, []byte("nonul")); err == nil {
		t.Fatal("expected error for regex missing pattern terminator")
	}
	if _, err := valueLen(bsonRegex, append([]byte("pat"), 0)); err == nil {
		t.Fatal("expected error for regex missing options terminator")
	}
	// string with negative/truncated length
	if _, err := valueLen(bsonString, []byte{1, 2}); err == nil {
		t.Fatal("expected error for truncated string length prefix")
	}
}

// ---- readBSONString edge cases ----

func TestReadBSONString_Malformed(t *testing.T) {
	if got := readBSONString([]byte{1, 2}); got != "" {
		t.Fatalf("expected empty string for too-short value, got %q", got)
	}
	// l < 1
	zero := make([]byte, 5)
	binary.LittleEndian.PutUint32(zero, 0)
	if got := readBSONString(zero); got != "" {
		t.Fatalf("expected empty string for zero length, got %q", got)
	}
	// l overflows available bytes
	over := make([]byte, 5)
	binary.LittleEndian.PutUint32(over, 100)
	if got := readBSONString(over); got != "" {
		t.Fatalf("expected empty string for overflowing length, got %q", got)
	}
}

// ---- parseCommandInfo / parseCommandDoc edge cases ----

func TestParseCommandInfo_TooShortHeader(t *testing.T) {
	if _, ok := parseCommandInfo(make([]byte, headerLen)); ok {
		t.Fatal("expected unresolved for a message with no body section")
	}
}

func TestParseCommandInfo_NonZeroFirstSectionKind(t *testing.T) {
	msg := make([]byte, 21)
	msg[20] = 1 // not kind 0
	binary.LittleEndian.PutUint32(msg[0:4], uint32(len(msg)))
	if _, ok := parseCommandInfo(msg); ok {
		t.Fatal("expected unresolved when the first section isn't kind 0")
	}
}

func TestParseCommandInfo_DeclaredLengthOverflows(t *testing.T) {
	msg := make([]byte, 25)
	msg[20] = 0
	binary.LittleEndian.PutUint32(msg[21:25], 1000) // way bigger than remaining bytes
	binary.LittleEndian.PutUint32(msg[0:4], uint32(len(msg)))
	if _, ok := parseCommandInfo(msg); ok {
		t.Fatal("expected unresolved when the declared body length overflows the message")
	}
}

func TestParseCommandInfo_ChecksumPresentTrimsTail(t *testing.T) {
	req := opMsgRequest(findCommand("orders", "shop"), 1)
	binary.LittleEndian.PutUint32(req[16:20], flagChecksumPresent)
	req = append(req, 0, 0, 0, 0) // fake checksum
	binary.LittleEndian.PutUint32(req[0:4], uint32(len(req)))
	info, ok := parseCommandInfo(req)
	if !ok || info.collection != "orders" {
		t.Fatalf("expected resolved find command despite checksum, got %+v %v", info, ok)
	}
}

func TestParseCommandDoc_TotalLengthMismatch(t *testing.T) {
	doc := bdoc(estring("find", "orders"), estring("$db", "shop"))
	doc[len(doc)-1] = 0xFF // corrupt the trailing NUL
	if _, ok := parseCommandDoc(doc); ok {
		t.Fatal("expected unresolved for a document missing its trailing NUL")
	}
}

func TestParseCommandDoc_UnterminatedElementName(t *testing.T) {
	// Build a doc whose single element's name cstring is never NUL-terminated.
	body := []byte{bsonString}
	body = append(body, "find"...) // no NUL terminator
	total := 4 + len(body) + 1
	out := make([]byte, 4, total)
	out = append(out, body...)
	out = append(out, 0x00)
	binary.LittleEndian.PutUint32(out, uint32(len(out)))
	if _, ok := parseCommandDoc(out); ok {
		t.Fatal("expected unresolved for an unterminated element name")
	}
}

func TestParseCommandDoc_ValueLenOverflow(t *testing.T) {
	// A string element claiming a length far beyond the document's actual size.
	e := []byte{bsonString}
	e = append(e, "find"...)
	e = append(e, 0)
	badLen := make([]byte, 4)
	binary.LittleEndian.PutUint32(badLen, 1000)
	e = append(e, badLen...)
	total := 4 + len(e) + 1
	out := make([]byte, 4, total)
	out = append(out, e...)
	out = append(out, 0x00)
	binary.LittleEndian.PutUint32(out, uint32(len(out)))
	if _, ok := parseCommandDoc(out); ok {
		t.Fatal("expected unresolved when a value length overflows the document")
	}
}

func TestParseCommandDoc_MissingDbUnresolved(t *testing.T) {
	doc := bdoc(estring("find", "orders")) // no $db field
	if _, ok := parseCommandDoc(doc); ok {
		t.Fatal("expected unresolved when $db is missing")
	}
}

func TestParseCommandDoc_TooShort(t *testing.T) {
	if _, ok := parseCommandDoc([]byte{1, 2, 3}); ok {
		t.Fatal("expected unresolved for a too-short doc")
	}
}

// ---- rewriteDoc error paths ----

func TestRewriteDoc_TooShort(t *testing.T) {
	if _, err := rewriteDoc([]byte{1, 2}, func(byte, string, []byte) ([]byte, error) { return nil, nil }); err == nil {
		t.Fatal("expected an error for a too-short document")
	}
}

func TestRewriteDoc_LengthMismatch(t *testing.T) {
	doc := bdoc(estring("a", "b"))
	doc[len(doc)-1] = 0xFF
	if _, err := rewriteDoc(doc, func(byte, string, []byte) ([]byte, error) { return nil, nil }); err == nil {
		t.Fatal("expected an error when the trailing NUL is corrupted")
	}
}

func TestRewriteDoc_UnterminatedName(t *testing.T) {
	body := []byte{bsonString}
	body = append(body, "find"...) // unterminated
	total := 4 + len(body) + 1
	out := make([]byte, 4, total)
	out = append(out, body...)
	out = append(out, 0x00)
	binary.LittleEndian.PutUint32(out, uint32(len(out)))
	if _, err := rewriteDoc(out, func(byte, string, []byte) ([]byte, error) { return nil, nil }); err == nil {
		t.Fatal("expected an error for an unterminated element name")
	}
}

func TestRewriteDoc_ValueLenError(t *testing.T) {
	doc := bdoc(estring("a", "b"))
	// Corrupt the type byte of the single element to something unrecognized by valueLen.
	doc[4] = 0x99
	if _, err := rewriteDoc(doc, func(byte, string, []byte) ([]byte, error) { return nil, nil }); err == nil {
		t.Fatal("expected an error for an unrecognized element type")
	}
}

func TestRewriteDoc_ValueOverflowsBody(t *testing.T) {
	e := []byte{bsonString}
	e = append(e, "a"...)
	e = append(e, 0)
	badLen := make([]byte, 4)
	binary.LittleEndian.PutUint32(badLen, 1000)
	e = append(e, badLen...)
	total := 4 + len(e) + 1
	out := make([]byte, 4, total)
	out = append(out, e...)
	out = append(out, 0x00)
	binary.LittleEndian.PutUint32(out, uint32(len(out)))
	if _, err := rewriteDoc(out, func(byte, string, []byte) ([]byte, error) { return nil, nil }); err == nil {
		t.Fatal("expected an error when the value length overflows the body")
	}
}

func TestRewriteDoc_FnError(t *testing.T) {
	doc := bdoc(estring("a", "b"))
	wantErr := errors.New("boom")
	_, err := rewriteDoc(doc, func(byte, string, []byte) ([]byte, error) { return nil, wantErr })
	if !errors.Is(err, wantErr) {
		t.Fatalf("expected fn's error to propagate, got %v", err)
	}
}

// ---- renderTopLevelDoc ----

func TestRenderTopLevelDoc_AllTypes(t *testing.T) {
	doc := bdoc(
		estring("name", "Alice"),
		enested(bsonDoc, "nested", bdoc()),
		func() []byte { // bsonNull element
			e := []byte{bsonNull}
			e = append(e, cstr("gone")...)
			return e
		}(),
		eint32("age", 30),
	)
	out := renderTopLevelDoc(doc)
	if !bytes.Contains([]byte(out), []byte("name=Alice")) {
		t.Fatalf("missing name field in %q", out)
	}
	if !bytes.Contains([]byte(out), []byte("nested=<nested>")) {
		t.Fatalf("missing nested rendering in %q", out)
	}
	if !bytes.Contains([]byte(out), []byte("gone=NULL")) {
		t.Fatalf("missing null rendering in %q", out)
	}
	if !bytes.Contains([]byte(out), []byte("age=<4 bytes>")) {
		t.Fatalf("missing default rendering in %q", out)
	}
}

func TestRenderTopLevelDoc_MalformedStringFallback(t *testing.T) {
	e := []byte{bsonString}
	e = append(e, cstr("bad")...)
	badLen := make([]byte, 4)
	binary.LittleEndian.PutUint32(badLen, 0) // l < 1
	e = append(e, badLen...)
	total := 4 + len(e) + 1
	out := make([]byte, 4, total)
	out = append(out, e...)
	out = append(out, 0x00)
	binary.LittleEndian.PutUint32(out, uint32(len(out)))
	got := renderTopLevelDoc(out)
	if !bytes.Contains([]byte(got), []byte("bad=<string>")) {
		t.Fatalf("expected fallback rendering for malformed string, got %q", got)
	}
}

// ---- result / maskString error propagation ----

func TestResult_MaskerErrorPropagates(t *testing.T) {
	doc := bdoc(estring("email", "err@example.com"))
	bm := &bsonMasker{ctx: context.Background(), masker: errMasker{}}
	if _, err := bm.result(doc, ""); !errors.Is(err, mask.ErrMaskerUnavailable) {
		t.Fatalf("expected ErrMaskerUnavailable, got %v", err)
	}
}

// TestResult_DeeplyNestedDocumentRejectedNotStackOverflow is the regression test for
// maxBSONNestingDepth. result recurses once per nesting level (bsonDoc/bsonArray); before the depth
// cap existed, a document nesting a near-empty sub-document recursively — well within the wire
// message's own 64 MiB size budget — would drive Go's goroutine stack past its limit and crash the
// whole process with an unrecoverable "fatal error: stack overflow" (recover() cannot catch this,
// unlike an ordinary panic — see wire.SafeGo's doc comment). It must now be rejected as an ordinary
// error, well before the stack has any chance to overflow.
func TestResult_DeeplyNestedDocumentRejectedNotStackOverflow(t *testing.T) {
	doc := bdoc(eint32("leaf", 1))
	for i := 0; i < maxBSONNestingDepth+10; i++ {
		doc = bdoc(enested(bsonDoc, "n", doc))
	}
	bm := &bsonMasker{ctx: context.Background(), masker: mask.Noop{}}
	if _, err := bm.result(doc, ""); !errors.Is(err, errBSONTooDeep) {
		t.Fatalf("expected errBSONTooDeep, got %v", err)
	}
}

// TestResult_NestingAtLimitStillWorks confirms the depth cap doesn't reject legitimate, merely
// deep (not adversarial) documents right at the boundary.
func TestResult_NestingAtLimitStillWorks(t *testing.T) {
	doc := bdoc(estring("leaf", "hello"))
	for i := 0; i < maxBSONNestingDepth; i++ {
		doc = bdoc(enested(bsonDoc, "n", doc))
	}
	bm := &bsonMasker{ctx: context.Background(), masker: mask.Noop{}}
	if _, err := bm.result(doc, ""); err != nil {
		t.Fatalf("expected a document exactly at the depth limit to succeed, got %v", err)
	}
}

func TestMaskString_MalformedValuePassesThrough(t *testing.T) {
	bm := &bsonMasker{ctx: context.Background(), masker: mask.NewOverlay(map[string]string{"x": "y"})}
	short := []byte{1, 2}
	out, err := bm.maskString("x", "x", short)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !bytes.Equal(out, short) {
		t.Fatal("malformed value must pass through unchanged")
	}
}

// ---- observe: non-OP_MSG and too-short messages are silently skipped ----

func TestRequestTracker_ObserveIgnoresNonOpMsg(t *testing.T) {
	tr := newRequestTracker()
	msg := make([]byte, headerLen)
	binary.LittleEndian.PutUint32(msg[12:16], 1) // opcode 1, not OP_MSG
	tr.observe(msg)
	if len(tr.pending) != 0 {
		t.Fatal("expected non-OP_MSG messages to be ignored")
	}
}

func TestRequestTracker_ObserveIgnoresTooShort(t *testing.T) {
	tr := newRequestTracker()
	tr.observe([]byte{1, 2, 3})
	if len(tr.pending) != 0 {
		t.Fatal("expected a too-short message to be ignored")
	}
}

// ---- bytesEqual ----

func TestBytesEqual(t *testing.T) {
	if !bytesEqual([]byte("abc"), []byte("abc")) {
		t.Fatal("expected equal byte slices to compare equal")
	}
	if bytesEqual([]byte("abc"), []byte("abd")) {
		t.Fatal("expected differing byte slices to compare unequal")
	}
	if bytesEqual([]byte("abc"), []byte("ab")) {
		t.Fatal("expected differing lengths to compare unequal")
	}
}
