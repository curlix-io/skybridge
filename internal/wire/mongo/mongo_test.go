package mongo

import (
	"bufio"
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"testing"

	"github.com/curlix-io/skybridge/internal/mask"
	"github.com/curlix-io/skybridge/internal/wire"
)

// errMasker always fails, simulating a masking-service outage under strict mode.
type errMasker struct{}

func (errMasker) MaskRow(context.Context, []mask.Column, [][]byte) ([][]byte, error) {
	return nil, mask.ErrMaskerUnavailable
}

func cstr(s string) []byte { return append([]byte(s), 0x00) }

func estring(name, val string) []byte {
	e := []byte{bsonString}
	e = append(e, cstr(name)...)
	v := make([]byte, 4)
	binary.LittleEndian.PutUint32(v, uint32(len(val)+1))
	v = append(v, val...)
	v = append(v, 0x00)
	return append(e, v...)
}

func eint32(name string, val int32) []byte {
	e := []byte{bsonInt32}
	e = append(e, cstr(name)...)
	b := make([]byte, 4)
	binary.LittleEndian.PutUint32(b, uint32(val))
	return append(e, b...)
}

func enested(typ byte, name string, doc []byte) []byte {
	e := []byte{typ}
	e = append(e, cstr(name)...)
	return append(e, doc...)
}

func bdoc(elems ...[]byte) []byte {
	var body []byte
	for _, e := range elems {
		body = append(body, e...)
	}
	out := make([]byte, 4, 5+len(body))
	out = append(out, body...)
	out = append(out, 0x00)
	binary.LittleEndian.PutUint32(out, uint32(len(out)))
	return out
}

func opMsgReply(body []byte) []byte {
	return opMsgReplyTo(body, 0)
}

// opMsgReplyTo builds an OP_MSG reply whose header's responseTo field is responseTo.
func opMsgReplyTo(body []byte, responseTo int32) []byte {
	msg := make([]byte, 20)
	binary.LittleEndian.PutUint32(msg[8:12], uint32(responseTo))
	binary.LittleEndian.PutUint32(msg[12:16], opMsg)
	msg = append(msg, 0) // section kind 0 (body)
	msg = append(msg, body...)
	binary.LittleEndian.PutUint32(msg[0:4], uint32(len(msg)))
	return msg
}

// opMsgRequest builds an OP_MSG client request whose header's requestID field is requestID.
func opMsgRequest(body []byte, requestID int32) []byte {
	msg := make([]byte, 20)
	binary.LittleEndian.PutUint32(msg[4:8], uint32(requestID))
	binary.LittleEndian.PutUint32(msg[12:16], opMsg)
	msg = append(msg, 0) // section kind 0 (body)
	msg = append(msg, body...)
	binary.LittleEndian.PutUint32(msg[0:4], uint32(len(msg)))
	return msg
}

// findCommand builds a { find: collection, filter: {}, $db: db } command body.
func findCommand(collection, db string) []byte {
	return bdoc(estring("find", collection), enested(bsonDoc, "filter", bdoc()), estring("$db", db))
}

// getMoreCommand builds a { getMore: cursorID, collection: collection, $db: db } command body.
func getMoreCommand(cursorID int64, collection, db string) []byte {
	e := []byte{bsonInt64}
	e = append(e, cstr("getMore")...)
	b := make([]byte, 8)
	binary.LittleEndian.PutUint64(b, uint64(cursorID))
	e = append(e, b...)
	return bdoc(e, estring("collection", collection), estring("$db", db))
}

// findReplyBody builds the body document a findReply wraps in an OP_MSG.
func findReplyBody() []byte {
	doc0 := bdoc(estring("email", "alice@example.com"), estring("name", "Alice"))
	doc1 := bdoc(estring("email", "bob@example.com"))
	batch := bdoc(enested(bsonDoc, "0", doc0), enested(bsonDoc, "1", doc1))
	cursor := bdoc(enested(bsonArray, "firstBatch", batch), estring("ns", "test.users"))
	return bdoc(enested(bsonDoc, "cursor", cursor), eint32("ok", 1))
}

// findReply builds a realistic find reply: { cursor: { firstBatch: [ {email,name}, {email} ],
// ns: "test.users" }, ok: 1 }.
func findReply() []byte {
	doc0 := bdoc(estring("email", "alice@example.com"), estring("name", "Alice"))
	doc1 := bdoc(estring("email", "bob@example.com"))
	batch := bdoc(enested(bsonDoc, "0", doc0), enested(bsonDoc, "1", doc1))
	cursor := bdoc(enested(bsonArray, "firstBatch", batch), estring("ns", "test.users"))
	body := bdoc(enested(bsonDoc, "cursor", cursor), eint32("ok", 1))
	return opMsgReply(body)
}

func TestTransformMessageMasksBatch(t *testing.T) {
	bm := &bsonMasker{ctx: context.Background(), masker: mask.NewOverlay(map[string]string{"email": "[redacted]"})}
	out, err := transformMessage(bm, findReply())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if bytes.Contains(out, []byte("alice@example.com")) || bytes.Contains(out, []byte("bob@example.com")) {
		t.Fatal("output still contains plaintext emails")
	}
	if bytes.Count(out, []byte("[redacted]")) != 2 {
		t.Fatalf("want 2 redactions, got %d", bytes.Count(out, []byte("[redacted]")))
	}
	// Non-PII fields must survive: the row name and the namespace string.
	if !bytes.Contains(out, []byte("Alice")) {
		t.Fatal("non-PII field 'Alice' lost")
	}
	if !bytes.Contains(out, []byte("test.users")) {
		t.Fatal("namespace string was masked (should only touch batch rows)")
	}
	// Re-framed length must match actual size.
	if int(binary.LittleEndian.Uint32(out[0:4])) != len(out) {
		t.Fatal("message length header not recomputed")
	}
}

func TestTransformMessageNoopUnchanged(t *testing.T) {
	bm := &bsonMasker{ctx: context.Background(), masker: mask.Noop{}}
	in := findReply()
	out, err := transformMessage(bm, in)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !bytes.Equal(out, in) {
		t.Fatal("Noop masker must leave the message byte-identical")
	}
}

func TestTransformMessageNonOpMsgPassthrough(t *testing.T) {
	bm := &bsonMasker{ctx: context.Background(), masker: mask.NewOverlay(map[string]string{"email": "x"})}
	// opcode 1 (OP_REPLY) must pass through untouched.
	msg := make([]byte, 20)
	binary.LittleEndian.PutUint32(msg[12:16], 1)
	binary.LittleEndian.PutUint32(msg[0:4], uint32(len(msg)))
	out, err := transformMessage(bm, msg)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !bytes.Equal(out, msg) {
		t.Fatal("non OP_MSG opcode was modified")
	}
}

func TestTransformMessageChecksumDropped(t *testing.T) {
	in := findReply()
	// Set checksumPresent flag and append a fake 4-byte CRC.
	binary.LittleEndian.PutUint32(in[16:20], flagChecksumPresent)
	in = append(in, 0xDE, 0xAD, 0xBE, 0xEF)
	binary.LittleEndian.PutUint32(in[0:4], uint32(len(in)))

	bm := &bsonMasker{ctx: context.Background(), masker: mask.NewOverlay(map[string]string{"email": "[redacted]"})}
	out, err := transformMessage(bm, in)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if binary.LittleEndian.Uint32(out[16:20])&flagChecksumPresent != 0 {
		t.Fatal("checksumPresent flag should be cleared after modification")
	}
	if int(binary.LittleEndian.Uint32(out[0:4])) != len(out) {
		t.Fatal("length header mismatch")
	}
	if bytes.Contains(out, []byte("alice@example.com")) {
		t.Fatal("email not masked")
	}
}

func TestTransformMessageErrorsOnMaskerFailure(t *testing.T) {
	bm := &bsonMasker{ctx: context.Background(), masker: errMasker{}}
	_, err := transformMessage(bm, findReply())
	if !errors.Is(err, mask.ErrMaskerUnavailable) {
		t.Fatalf("expected ErrMaskerUnavailable, got %v", err)
	}
}

func TestMaskServerAbortsOnMaskerFailure(t *testing.T) {
	in := findReply()
	var out bytes.Buffer
	r := bufio.NewReader(bytes.NewReader(in))
	err := maskServer(context.Background(), r, &out, errMasker{}, wire.NoopRecorder{}, newRequestTracker(), "", nil)
	if !errors.Is(err, mask.ErrMaskerUnavailable) {
		t.Fatalf("expected ErrMaskerUnavailable, got %v", err)
	}
	if bytes.Contains(out.Bytes(), []byte("alice@example.com")) {
		t.Fatal("unmasked email must never reach the client when the masker fails in strict mode")
	}
}

func TestMaskServerEndToEnd(t *testing.T) {
	in := findReply()
	var out bytes.Buffer
	r := bufio.NewReader(bytes.NewReader(in))
	overlay := mask.NewOverlay(map[string]string{"email": "[redacted]"})
	_ = maskServer(context.Background(), r, &out, overlay, wire.NoopRecorder{}, newRequestTracker(), "", nil)

	if bytes.Contains(out.Bytes(), []byte("alice@example.com")) {
		t.Fatal("email leaked through maskServer")
	}
	if !bytes.Contains(out.Bytes(), []byte("[redacted]")) {
		t.Fatal("masking not applied")
	}
}

// colCapturingMasker records the mask.Column slice it was called with (per invocation) and applies
// no masking, so tests can assert on ObjectID/Path without depending on Overlay/PathOverlay.
type colCapturingMasker struct {
	calls [][]mask.Column
}

func (m *colCapturingMasker) MaskRow(_ context.Context, cols []mask.Column, row [][]byte) ([][]byte, error) {
	m.calls = append(m.calls, append([]mask.Column(nil), cols...))
	return row, nil
}

func TestParseCommandInfo_Find(t *testing.T) {
	req := opMsgRequest(findCommand("orders", "shop"), 42)
	info, ok := parseCommandInfo(req)
	if !ok {
		t.Fatal("expected parseCommandInfo to resolve a find command")
	}
	if info.collection != "orders" || info.db != "shop" {
		t.Fatalf("got %+v", info)
	}
}

func TestParseCommandInfo_GetMore(t *testing.T) {
	req := opMsgRequest(getMoreCommand(123, "orders", "shop"), 43)
	info, ok := parseCommandInfo(req)
	if !ok {
		t.Fatal("expected parseCommandInfo to resolve a getMore command")
	}
	if info.collection != "orders" || info.db != "shop" {
		t.Fatalf("got %+v", info)
	}
}

func TestParseCommandInfo_UnknownCommandUnresolved(t *testing.T) {
	body := bdoc(eint32("hello", 1), estring("$db", "admin"))
	req := opMsgRequest(body, 44)
	if _, ok := parseCommandInfo(req); ok {
		t.Fatal("expected an unrecognized command to be unresolved")
	}
}

func TestParseCommandInfo_MalformedUnresolved(t *testing.T) {
	if _, ok := parseCommandInfo([]byte{1, 2, 3}); ok {
		t.Fatal("expected malformed input to be unresolved")
	}
}

func TestRequestTracker_ObserveAndResolve(t *testing.T) {
	tr := newRequestTracker()
	tr.observe(opMsgRequest(findCommand("orders", "shop"), 7))
	info, ok := tr.resolve(7)
	if !ok || info.collection != "orders" || info.db != "shop" {
		t.Fatalf("resolve(7) = %+v, %v", info, ok)
	}
	// resolve consumes the entry.
	if _, ok := tr.resolve(7); ok {
		t.Fatal("expected resolve to consume the tracked entry")
	}
}

func TestRequestTracker_UnknownResponseToUnresolved(t *testing.T) {
	tr := newRequestTracker()
	if _, ok := tr.resolve(999); ok {
		t.Fatal("expected an untracked responseTo to be unresolved")
	}
}

func TestRequestTracker_BoundedSize(t *testing.T) {
	tr := newRequestTracker()
	for i := int32(0); i < maxTrackedRequests+10; i++ {
		tr.observe(opMsgRequest(findCommand("orders", "shop"), i))
	}
	if len(tr.pending) > maxTrackedRequests {
		t.Fatalf("tracker grew unbounded: %d entries", len(tr.pending))
	}
}

func TestBSONMasker_ObjectIDResolvedFromTrackedRequest(t *testing.T) {
	tr := newRequestTracker()
	tr.observe(opMsgRequest(findCommand("orders", "shop"), 7))

	cm := &colCapturingMasker{}
	bm := &bsonMasker{ctx: context.Background(), masker: cm, tracker: tr, orgID: "org1"}
	if _, err := transformMessage(bm, opMsgReplyTo(findReplyBody(), 7)); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(cm.calls) == 0 {
		t.Fatal("expected masker to be invoked")
	}
	for _, cols := range cm.calls {
		for _, c := range cols {
			if c.ObjectID != "org1:mongo:shop:orders" {
				t.Fatalf("got ObjectID %q, want org1:mongo:shop:orders", c.ObjectID)
			}
		}
	}
}

func TestBSONMasker_ObjectIDEmptyWhenUnresolved(t *testing.T) {
	cm := &colCapturingMasker{}
	bm := &bsonMasker{ctx: context.Background(), masker: cm, tracker: newRequestTracker(), orgID: "org1"}
	if _, err := transformMessage(bm, findReply()); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	for _, cols := range cm.calls {
		for _, c := range cols {
			if c.ObjectID != "" {
				t.Fatalf("got ObjectID %q, want empty (no matching tracked request)", c.ObjectID)
			}
		}
	}
}

func TestBSONMasker_NestedPathResolved(t *testing.T) {
	nested := bdoc(estring("email", "jane@doe.com"))
	doc0 := bdoc(enested(bsonDoc, "profile", nested))
	batch := bdoc(enested(bsonDoc, "0", doc0))
	cursor := bdoc(enested(bsonArray, "firstBatch", batch))
	body := bdoc(enested(bsonDoc, "cursor", cursor))
	reply := opMsgReply(body)

	cm := &colCapturingMasker{}
	bm := &bsonMasker{ctx: context.Background(), masker: cm}
	if _, err := transformMessage(bm, reply); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	var gotPath string
	for _, cols := range cm.calls {
		for _, c := range cols {
			if c.Name == "email" {
				gotPath = c.Path
			}
		}
	}
	if gotPath != "profile.email" {
		t.Fatalf("got Path %q, want profile.email", gotPath)
	}
}

func TestValueLen(t *testing.T) {
	if n, err := valueLen(bsonInt32, []byte{1, 0, 0, 0}); err != nil || n != 4 {
		t.Fatalf("int32: %d %v", n, err)
	}
	if n, err := valueLen(bsonObjectID, make([]byte, 12)); err != nil || n != 12 {
		t.Fatalf("objectid: %d %v", n, err)
	}
	str := append([]byte{4, 0, 0, 0}, []byte("abc")...)
	str = append(str, 0x00)
	if n, err := valueLen(bsonString, str); err != nil || n != 8 {
		t.Fatalf("string: %d %v", n, err)
	}
	if _, err := valueLen(0x99, []byte{0}); err == nil {
		t.Fatal("expected error for unknown type")
	}
}
