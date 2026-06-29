package mongo

import (
	"bufio"
	"bytes"
	"context"
	"encoding/binary"
	"testing"

	"github.com/curlix-io/skybridge/internal/mask"
)

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
	msg := make([]byte, 20)
	binary.LittleEndian.PutUint32(msg[12:16], opMsg)
	msg = append(msg, 0) // section kind 0 (body)
	msg = append(msg, body...)
	binary.LittleEndian.PutUint32(msg[0:4], uint32(len(msg)))
	return msg
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
	out := transformMessage(bm, findReply())

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
	out := transformMessage(bm, in)
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
	if out := transformMessage(bm, msg); !bytes.Equal(out, msg) {
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
	out := transformMessage(bm, in)

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

func TestMaskServerEndToEnd(t *testing.T) {
	in := findReply()
	var out bytes.Buffer
	r := bufio.NewReader(bytes.NewReader(in))
	overlay := mask.NewOverlay(map[string]string{"email": "[redacted]"})
	_ = maskServer(context.Background(), r, &out, overlay)

	if bytes.Contains(out.Bytes(), []byte("alice@example.com")) {
		t.Fatal("email leaked through maskServer")
	}
	if !bytes.Contains(out.Bytes(), []byte("[redacted]")) {
		t.Fatal("masking not applied")
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
