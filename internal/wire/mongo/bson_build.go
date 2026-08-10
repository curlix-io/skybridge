// Generic BSON document read/write helpers for the auth handshake (clientauth.go/auth.go).
// bson.go's parseCommandDoc is intentionally narrow (only extracts collection/$db for the masking
// path's identity tracking) — auth commands (hello/saslStart/saslContinue) need arbitrary field
// access (mechanism, payload, $db, conversationId, ok, done), so this file adds a small generic
// element map plus minimal document/message builders. Kept separate from bson.go's masking-path
// primitives to keep that file's narrow contract legible.
package mongo

import (
	"bytes"
	"encoding/binary"
	"math"
)

// bsonElem is one parsed top-level BSON element: its type byte and raw value bytes (as returned
// by valueLen — same convention as rewriteDoc/parseCommandDoc).
type bsonElem struct {
	typ   byte
	value []byte
}

// parseCommandDocGeneric parses a client OP_MSG command's top-level body document (section kind 0)
// into a name->element map, for commands whose shape bson.go's narrow parseCommandDoc doesn't
// cover (hello, saslStart, saslContinue). Malformed input returns ok=false, never a panic.
func parseCommandDocGeneric(msg []byte) (map[string]bsonElem, bool) {
	if len(msg) < headerLen+4 {
		return nil, false
	}
	flags := binary.LittleEndian.Uint32(msg[16:20])
	end := len(msg)
	if flags&flagChecksumPresent != 0 {
		end -= 4
	}
	if end < 21 || msg[20] != 0 { // first section must be kind 0 (body document)
		return nil, false
	}
	if end < 25 {
		return nil, false
	}
	dl := int(binary.LittleEndian.Uint32(msg[21:25]))
	if dl < 5 || 21+dl > end {
		return nil, false
	}
	return parseDocGeneric(msg[21 : 21+dl])
}

func parseDocGeneric(doc []byte) (map[string]bsonElem, bool) {
	if len(doc) < 5 {
		return nil, false
	}
	total := int(binary.LittleEndian.Uint32(doc))
	if total != len(doc) || doc[total-1] != 0x00 {
		return nil, false
	}
	body := doc[4 : total-1]
	out := map[string]bsonElem{}
	off := 0
	for off < len(body) {
		typ := body[off]
		off++
		nend := bytes.IndexByte(body[off:], 0x00)
		if nend < 0 {
			return nil, false
		}
		name := string(body[off : off+nend])
		off += nend + 1
		vlen, err := valueLen(typ, body[off:])
		if err != nil || off+vlen > len(body) {
			return nil, false
		}
		out[name] = bsonElem{typ: typ, value: body[off : off+vlen]}
		off += vlen
	}
	return out, true
}

func fieldNames(doc map[string]bsonElem) []string {
	names := make([]string, 0, len(doc))
	for k := range doc {
		names = append(names, k)
	}
	return names
}

// stringField reads a BSON string field, "" if absent or a different type.
func stringField(doc map[string]bsonElem, name string) string {
	e, ok := doc[name]
	if !ok || e.typ != bsonString {
		return ""
	}
	return readBSONString(e.value)
}

// binaryField reads a BSON binary field's payload bytes (subtype ignored — the PLAIN payload is
// read regardless of whether a driver sends subtype 0x00 generic binary, the spec default).
// Returns nil if absent or a different type.
func binaryField(doc map[string]bsonElem, name string) []byte {
	e, ok := doc[name]
	if !ok || e.typ != bsonBinary {
		return nil
	}
	if len(e.value) < 5 {
		return nil
	}
	l := int(binary.LittleEndian.Uint32(e.value))
	if l < 0 || 5+l > len(e.value) {
		return nil
	}
	return e.value[5 : 5+l]
}

// --- Minimal BSON document builders (writer side, for synthesizing hello/sasl replies) ---

type docBuilder struct{ body []byte }

func newDoc() *docBuilder { return &docBuilder{} }

func (d *docBuilder) addString(name, val string) *docBuilder {
	d.body = append(d.body, bsonString)
	d.body = append(d.body, name...)
	d.body = append(d.body, 0x00)
	v := make([]byte, 4)
	binary.LittleEndian.PutUint32(v, uint32(len(val)+1))
	d.body = append(d.body, v...)
	d.body = append(d.body, val...)
	d.body = append(d.body, 0x00)
	return d
}

func (d *docBuilder) addInt32(name string, val int32) *docBuilder {
	d.body = append(d.body, bsonInt32)
	d.body = append(d.body, name...)
	d.body = append(d.body, 0x00)
	v := make([]byte, 4)
	binary.LittleEndian.PutUint32(v, uint32(val))
	d.body = append(d.body, v...)
	return d
}

func (d *docBuilder) addBool(name string, val bool) *docBuilder {
	d.body = append(d.body, bsonBool)
	d.body = append(d.body, name...)
	d.body = append(d.body, 0x00)
	if val {
		d.body = append(d.body, 1)
	} else {
		d.body = append(d.body, 0)
	}
	return d
}

func (d *docBuilder) addBinary(name string, val []byte) *docBuilder {
	d.body = append(d.body, bsonBinary)
	d.body = append(d.body, name...)
	d.body = append(d.body, 0x00)
	v := make([]byte, 4)
	binary.LittleEndian.PutUint32(v, uint32(len(val)))
	d.body = append(d.body, v...)
	d.body = append(d.body, 0x00) // subtype 0x00, generic binary
	d.body = append(d.body, val...)
	return d
}

func (d *docBuilder) addDouble(name string, val float64) *docBuilder {
	d.body = append(d.body, bsonDouble)
	d.body = append(d.body, name...)
	d.body = append(d.body, 0x00)
	bits := make([]byte, 8)
	binary.LittleEndian.PutUint64(bits, math.Float64bits(val))
	d.body = append(d.body, bits...)
	return d
}

func (d *docBuilder) bytes() []byte {
	out := make([]byte, 4, 5+len(d.body))
	out = append(out, d.body...)
	out = append(out, 0x00)
	binary.LittleEndian.PutUint32(out, uint32(len(out)))
	return out
}

// opMsgReplyMessage builds a complete OP_MSG server reply (single body-document section, no
// checksum) with responseTo set to requestID, matching the shape opMsgReplyTo builds in tests but
// exported for production use here (server->client direction).
func opMsgReplyMessage(body []byte, responseTo int32) []byte {
	msg := make([]byte, 20)
	binary.LittleEndian.PutUint32(msg[8:12], uint32(responseTo))
	binary.LittleEndian.PutUint32(msg[12:16], opMsg)
	msg = append(msg, 0) // section kind 0 (body)
	msg = append(msg, body...)
	binary.LittleEndian.PutUint32(msg[0:4], uint32(len(msg)))
	return msg
}

// helloReply builds a minimal, self-consistent hello/isMaster response advertising a recent
// maxWireVersion (so drivers proceed normally) — no saslSupportedMechs (see clientauth.go's
// package doc: this proxy does not attempt to make a driver auto-discover PLAIN; the client must
// already be configured with authMechanism=PLAIN).
func helloReply(responseTo int32) []byte {
	doc := newDoc().
		addBool("ismaster", true).
		addInt32("maxBsonObjectSize", 16777216).
		addInt32("maxMessageSizeBytes", 48000000).
		addInt32("maxWriteBatchSize", 100000).
		addDouble("ok", 1).
		addInt32("maxWireVersion", 21).
		addInt32("minWireVersion", 0).
		addBool("readOnly", false).
		bytes()
	return opMsgReplyMessage(doc, responseTo)
}

// saslCompleteReply builds the single-round-trip PLAIN completion reply: {conversationId, done:
// true, payload: <empty>, ok: 1}.
func saslCompleteReply(responseTo int32) []byte {
	doc := newDoc().
		addInt32("conversationId", 1).
		addBool("done", true).
		addBinary("payload", nil).
		addDouble("ok", 1).
		bytes()
	return opMsgReplyMessage(doc, responseTo)
}
