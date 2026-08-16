package mongo

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"strings"

	"github.com/curlix-io/skybridge/internal/mask"
	"github.com/curlix-io/skybridge/internal/wire"
)

// BSON element type bytes (subset we need to know to walk values).
const (
	bsonDouble    = 0x01
	bsonString    = 0x02
	bsonDoc       = 0x03
	bsonArray     = 0x04
	bsonBinary    = 0x05
	bsonUndefined = 0x06
	bsonObjectID  = 0x07
	bsonBool      = 0x08
	bsonDatetime  = 0x09
	bsonNull      = 0x0A
	bsonRegex     = 0x0B
	bsonDBPointer = 0x0C
	bsonJS        = 0x0D
	bsonSymbol    = 0x0E
	bsonCodeScope = 0x0F
	bsonInt32     = 0x10
	bsonTimestamp = 0x11
	bsonInt64     = 0x12
	bsonDecimal   = 0x13
	bsonMinKey    = 0xFF
	bsonMaxKey    = 0x7F
)

var errBadBSON = errors.New("malformed bson")

// bsonTypeKind maps a subset of BSON scalar type bytes to mask.TypeKind, letting PathOverlay
// substitute a type-valid placeholder for a *confirmed* label's redaction request on a non-string
// field — see docs/PATH_LABEL_IDENTITY_GAPS_DESIGN.md's Gap B. Deliberately a strict subset of the
// scalar types valueLen recognizes: bsonRegex, bsonDBPointer, bsonJS/bsonCodeScope, bsonBinary,
// bsonTimestamp, bsonNull/bsonUndefined/bsonMinKey/bsonMaxKey have no entry on purpose — they're
// either never real user data (an internal replication Timestamp, a MinKey/MaxKey sentinel), have
// no meaningful "redacted" placeholder (Binary's subtype-specific payload), or their fixed-width
// zero value has no natural interpretation worth committing to. Only types present here are ever
// routed through masking at all (see result()); everything else keeps today's behavior of passing
// straight through, exactly as before Gap B's Mongo support existed.
var bsonTypeKind = map[byte]mask.TypeKind{
	bsonBool:     mask.TypeKindBool,
	bsonInt32:    mask.TypeKindNumeric,
	bsonInt64:    mask.TypeKindNumeric,
	bsonDouble:   mask.TypeKindNumeric,
	bsonDecimal:  mask.TypeKindNumeric,
	bsonDatetime: mask.TypeKindDate,
	bsonObjectID: mask.TypeKindObjectID,
}

// zeroValueBSON returns a fixed-width, all-zero BSON-encoded placeholder for typ — the value
// substituted in place of a redacted scalar's original bytes. Zero-filled rather than
// content-derived because, unlike Postgres/MySQL's text-protocol placeholders (a decimal digit
// string a client re-parses), a BSON scalar's bytes ARE the value in its native binary encoding:
// there is no separate "encode this placeholder" step, so the placeholder must already be a valid
// instance of the type — an all-zero int32/int64/double/datetime is 0, a zeroed ObjectID is the
// conventional "empty" sentinel client BSON libraries already special-case for a missing id, and
// false is the zero-valued bool. Panics if typ isn't a key of bsonTypeKind — callers only ever
// reach this after confirming a bsonTypeKind entry exists, so this is a programmer-error guard, not
// a runtime condition callers need to check for.
func zeroValueBSON(typ byte) []byte {
	switch typ {
	case bsonBool:
		return []byte{0x00}
	case bsonInt32:
		return make([]byte, 4)
	case bsonInt64, bsonDouble, bsonDatetime:
		return make([]byte, 8)
	case bsonDecimal:
		return make([]byte, 16)
	case bsonObjectID:
		return make([]byte, 12)
	default:
		panic(fmt.Sprintf("mongo: zeroValueBSON called for unmapped type 0x%02x", typ))
	}
}

// bsonMasker walks BSON documents and masks the string field values inside query result batches.
// Masking reuses the row masker (overlay by field name + remote masker on content), one string at a time.
// recorder, when non-nil, receives a rendered summary of each already-masked result document for
// session replay — see batch() below (coarser than postgres/mysql's per-column render, since BSON
// documents are arbitrarily nested; a full recursive render is a later refinement, not required for
// a first pass at Mongo replay).
type bsonMasker struct {
	ctx      context.Context
	masker   mask.Masker
	recorder wire.Recorder
	// tracker resolves the current reply's requestID to a database/collection learned from the
	// matching client request, for objectID below. nil (e.g. in unit tests exercising transformMessage
	// directly) behaves as "always unresolved" — same as a client request that failed to parse.
	tracker *requestTracker
	// orgID scopes curObjectID's result the same way mysql's Engine.orgID does; empty disables
	// path-scoped-label ObjectID resolution without otherwise affecting masking.
	orgID string
	// curObjectID is resolved once per reply message (see transformMessage, which calls
	// resolveObjectID before descending into the body) so cursor/batch/result, deep in the
	// recursion, can read the shared value without threading it through every call or re-resolving
	// (and thus re-consuming) the tracker entry per document in a batch.
	curObjectID string
	// collector, when non-nil, receives every free-text string field's pre-mask value keyed by
	// curObjectID/path, feeding an AI classifier's sample buffer
	// (internal/pathlabel/trafficsampler) instead of requiring a second, dedicated read-only DSN to
	// sample from (see docs/AI_PATH_LABELLING_DESIGN.md §5.2). nil leaves this a no-op, exactly as
	// before this feature existed.
	collector sampleCollector
}

// sampleCollector matches trafficsampler.Buffer's Observe method — kept as a local interface so this
// package doesn't import internal/pathlabel/trafficsampler just for a method set.
type sampleCollector interface {
	Observe(objectID, fieldPath, value string)
}

// resolveObjectID resolves and caches the tenant-scoped identifier mask.Column.ObjectID carries for
// this reply, e.g. "org1:mongo:app:orders" — "" when orgID is unset or the reply's originating
// request's collection couldn't be resolved (a path-aware Masker treats "" as "no label
// available"). Must be called exactly once per reply message, before any nested masking, since
// requestTracker.resolve consumes the tracked entry.
func (m *bsonMasker) resolveObjectID(responseTo int32) {
	if m.orgID == "" || m.tracker == nil {
		m.curObjectID = ""
		return
	}
	info, ok := m.tracker.resolve(responseTo)
	if !ok || info.collection == "" {
		m.curObjectID = ""
		return
	}
	m.curObjectID = m.orgID + ":mongo:" + info.db + ":" + info.collection
}

// dbCommands is the set of top-level command names whose value is the target collection —
// find/aggregate/count/distinct/insert/update/delete cover the shapes that return the result
// batches this engine masks or that a getMore later continues. Commands not in this set (hello,
// isMaster, ping, endSessions, ...) are intentionally left unresolved: they never carry a
// firstBatch/nextBatch this engine descends into, so there's nothing for an ObjectID to label.
var dbCommands = map[string]bool{
	"find": true, "aggregate": true, "count": true, "distinct": true,
	"insert": true, "update": true, "delete": true, "findAndModify": true,
}

// parseCommandInfo best-effort extracts the target database/collection from a client OP_MSG
// command message, read-only (never mutates msg). Returns ok=false on anything it doesn't
// recognize — malformed BSON, a non-command opcode, or a command outside dbCommands/getMore —
// which callers treat identically to "collection unknown," never as an error.
func parseCommandInfo(msg []byte) (collectionInfo, bool) {
	if len(msg) < headerLen+4 {
		return collectionInfo{}, false
	}
	flags := binary.LittleEndian.Uint32(msg[16:20])
	end := len(msg)
	if flags&flagChecksumPresent != 0 {
		end -= 4
	}
	if end < 21 || msg[20] != 0 { // first section must be kind 0 (body document)
		return collectionInfo{}, false
	}
	if end < 25 {
		return collectionInfo{}, false
	}
	dl := int(binary.LittleEndian.Uint32(msg[21:25]))
	if dl < 5 || 21+dl > end {
		return collectionInfo{}, false
	}
	return parseCommandDoc(msg[21 : 21+dl])
}

// parseCommandDoc reads a command body document's top-level fields to find its collection — the
// first key's string value when that key names a command in dbCommands (find/aggregate/...), or the
// "collection" string field getMore carries instead (its first key, "getMore", holds a cursor id,
// not a name) — and its "$db" string field.
func parseCommandDoc(doc []byte) (collectionInfo, bool) {
	if len(doc) < 5 {
		return collectionInfo{}, false
	}
	total := int(binary.LittleEndian.Uint32(doc))
	if total != len(doc) || doc[total-1] != 0x00 {
		return collectionInfo{}, false
	}
	body := doc[4 : total-1]

	var info collectionInfo
	first := true
	off := 0
	for off < len(body) {
		typ := body[off]
		off++
		nend := bytes.IndexByte(body[off:], 0x00)
		if nend < 0 {
			return collectionInfo{}, false
		}
		name := string(body[off : off+nend])
		off += nend + 1

		vlen, err := valueLen(typ, body[off:])
		if err != nil || off+vlen > len(body) {
			return collectionInfo{}, false
		}
		value := body[off : off+vlen]
		off += vlen

		switch {
		case first && typ == bsonString && dbCommands[name]:
			info.collection = readBSONString(value)
		case typ == bsonString && name == "collection":
			info.collection = readBSONString(value)
		case typ == bsonString && name == "$db":
			info.db = readBSONString(value)
		}
		first = false
	}
	if info.collection == "" || info.db == "" {
		return collectionInfo{}, false
	}
	return info, true
}

// readBSONString reads a BSON string value (int32 length + bytes + NUL), returning "" on any
// malformed input rather than an error — callers already treat "" as "unresolved."
func readBSONString(value []byte) string {
	if len(value) < 5 {
		return ""
	}
	l := int(binary.LittleEndian.Uint32(value))
	if l < 1 || 4+l > len(value) {
		return ""
	}
	return string(value[4 : 4+l-1])
}

type elemFn func(typ byte, name string, value []byte) ([]byte, error)

// rewriteDoc walks a complete BSON document (4-byte length prefix .. trailing 0x00) and rebuilds it,
// passing each element's value through fn. Lengths are recomputed so callers may grow/shrink values.
func rewriteDoc(doc []byte, fn elemFn) ([]byte, error) {
	if len(doc) < 5 {
		return nil, errBadBSON
	}
	total := int(binary.LittleEndian.Uint32(doc))
	if total != len(doc) || doc[total-1] != 0x00 {
		return nil, errBadBSON
	}
	body := doc[4 : total-1]

	out := make([]byte, 4, len(doc))
	off := 0
	for off < len(body) {
		typ := body[off]
		off++
		nend := bytes.IndexByte(body[off:], 0x00)
		if nend < 0 {
			return nil, errBadBSON
		}
		name := string(body[off : off+nend])
		nameBytes := body[off : off+nend+1] // includes the null terminator
		off += nend + 1

		vlen, err := valueLen(typ, body[off:])
		if err != nil {
			return nil, err
		}
		if off+vlen > len(body) {
			return nil, errBadBSON
		}
		value := body[off : off+vlen]
		off += vlen

		nv, err := fn(typ, name, value)
		if err != nil {
			return nil, err
		}
		out = append(out, typ)
		out = append(out, nameBytes...)
		out = append(out, nv...)
	}
	out = append(out, 0x00)
	binary.LittleEndian.PutUint32(out[0:4], uint32(len(out)))
	return out, nil
}

// valueLen returns the byte length of a BSON value of the given type at the start of b.
func valueLen(typ byte, b []byte) (int, error) {
	le32 := func() (int, bool) {
		if len(b) < 4 {
			return 0, false
		}
		return int(binary.LittleEndian.Uint32(b)), true
	}
	switch typ {
	case bsonDouble, bsonDatetime, bsonTimestamp, bsonInt64:
		return 8, nil
	case bsonInt32:
		return 4, nil
	case bsonObjectID:
		return 12, nil
	case bsonBool:
		return 1, nil
	case bsonNull, bsonUndefined, bsonMinKey, bsonMaxKey:
		return 0, nil
	case bsonDecimal:
		return 16, nil
	case bsonString, bsonJS, bsonSymbol:
		l, ok := le32()
		if !ok || l < 0 {
			return 0, errBadBSON
		}
		return 4 + l, nil
	case bsonBinary:
		l, ok := le32()
		if !ok || l < 0 {
			return 0, errBadBSON
		}
		return 4 + 1 + l, nil // length + subtype + bytes
	case bsonDoc, bsonArray, bsonCodeScope:
		l, ok := le32()
		if !ok || l < 5 {
			return 0, errBadBSON
		}
		return l, nil
	case bsonDBPointer:
		l, ok := le32()
		if !ok || l < 0 {
			return 0, errBadBSON
		}
		return 4 + l + 12, nil
	case bsonRegex:
		a := bytes.IndexByte(b, 0x00)
		if a < 0 {
			return 0, errBadBSON
		}
		c := bytes.IndexByte(b[a+1:], 0x00)
		if c < 0 {
			return 0, errBadBSON
		}
		return a + 1 + c + 1, nil
	default:
		return 0, errBadBSON
	}
}

// body masks a reply body document: only the cursor.{firstBatch,nextBatch} result arrays are
// descended into, so protocol/auth fields are never touched.
func (m *bsonMasker) body(doc []byte) ([]byte, error) {
	return rewriteDoc(doc, func(typ byte, name string, value []byte) ([]byte, error) {
		if typ == bsonDoc && name == "cursor" {
			return m.cursor(value)
		}
		return value, nil
	})
}

func (m *bsonMasker) cursor(doc []byte) ([]byte, error) {
	return rewriteDoc(doc, func(typ byte, name string, value []byte) ([]byte, error) {
		if typ == bsonArray && (name == "firstBatch" || name == "nextBatch") {
			return m.batch(value)
		}
		return value, nil
	})
}

// batch masks each result document inside a firstBatch/nextBatch array (array keys are "0","1",...),
// and — when a recorder is attached — records a rendered summary of the already-masked document
// for session replay.
func (m *bsonMasker) batch(arr []byte) ([]byte, error) {
	return rewriteDoc(arr, func(typ byte, _ string, value []byte) ([]byte, error) {
		if typ != bsonDoc {
			return value, nil
		}
		masked, err := m.result(value, "")
		if err != nil {
			return value, err
		}
		if m.recorder != nil {
			m.recorder.RecordOutput(renderTopLevelDoc(masked))
		}
		return masked, nil
	})
}

// renderTopLevelDoc formats a masked BSON document's top-level scalar/string fields as
// "field1=val1, field2=val2, ..." for the replay transcript — nested docs/arrays are rendered as
// "<nested>" rather than recursively expanded (a later refinement, not required for a first pass).
func renderTopLevelDoc(doc []byte) string {
	var b strings.Builder
	first := true
	_, _ = rewriteDoc(doc, func(typ byte, name string, value []byte) ([]byte, error) {
		if !first {
			b.WriteString(", ")
		}
		first = false
		b.WriteString(name)
		b.WriteByte('=')
		switch typ {
		case bsonString, bsonJS, bsonSymbol:
			if len(value) >= 5 {
				l := int(binary.LittleEndian.Uint32(value))
				if l >= 1 && 4+l <= len(value) {
					b.Write(value[4 : 4+l-1])
					break
				}
			}
			b.WriteString("<string>")
		case bsonDoc, bsonArray:
			b.WriteString("<nested>")
		case bsonNull, bsonUndefined:
			b.WriteString("NULL")
		default:
			fmt.Fprintf(&b, "<%d bytes>", len(value))
		}
		return value, nil
	})
	return b.String()
}

// maxBSONNestingDepth caps how many levels deep result recurses into nested docs/arrays, matching
// MongoDB's own server-side BSON depth limit. Without this, a document nesting a near-empty
// sub-document (~8 bytes) recursively fits millions of levels inside the wire message's own
// maxMessageBytes cap — each level costs Go stack frames in rewriteDoc/result, so an unbounded depth
// drives a stack-overflow *fatal error* well before that byte budget is exhausted. Unlike a panic,
// Go's runtime cannot recover from a stack overflow (see wire.SafeGo's doc comment), so this has to
// be prevented by construction rather than caught after the fact.
const maxBSONNestingDepth = 100

// errBSONTooDeep is returned when a document nests more than maxBSONNestingDepth levels deep.
var errBSONTooDeep = errors.New("mongo: bson document nesting exceeds limit")

// result masks every string field in a result document, recursing into nested docs/arrays. path is
// the dotted, index-erased resolved path to doc itself ("" at the top level, then e.g. "profile" for
// a nested doc under it), matching internal/pathlabel/docpath's path convention so PathOverlay's
// (ObjectID, Path) lookups behave the same for the wire proxy as for the dbquery exec path.
func (m *bsonMasker) result(doc []byte, path string) ([]byte, error) {
	return m.resultDepth(doc, path, 0)
}

func (m *bsonMasker) resultDepth(doc []byte, path string, depth int) ([]byte, error) {
	if depth > maxBSONNestingDepth {
		return nil, errBSONTooDeep
	}
	return rewriteDoc(doc, func(typ byte, name string, value []byte) ([]byte, error) {
		switch typ {
		case bsonString:
			return m.maskString(name, joinPath(path, name), value)
		case bsonDoc, bsonArray:
			return m.resultDepth(value, joinPath(path, name), depth+1)
		default:
			if _, ok := bsonTypeKind[typ]; ok {
				return m.maskScalar(name, joinPath(path, name), typ, value)
			}
			return value, nil
		}
	})
}

func joinPath(path, key string) string {
	if path == "" {
		return key
	}
	return path + "." + key
}

// maskScalar runs a single non-string BSON scalar value (bool/int32/int64/double/decimal128/
// datetime/objectId — see bsonTypeKind) through the masker with Text:true, FreeText:false, and the
// mapped TypeKind, so mask.Remote and Overlay both skip it (FreeText gates them off, same as every
// typed column in every engine) while PathOverlay's confirmed-label path still runs — see
// docs/PATH_LABEL_IDENTITY_GAPS_DESIGN.md's Gap B.
//
// PathOverlay returns a plain-string placeholder token (its typeValidPlaceholder table is written
// for SQL's text-protocol wire format), which is never a valid direct substitute for value's
// fixed-width BSON binary encoding — so this method only uses PathOverlay's response as a redact/
// don't-redact signal (did the bytes change at all?) and, on redact, substitutes zeroValueBSON(typ)
// — a real, fixed-width, zero-valued instance of the field's own BSON type — rather than the
// literal token bytes PathOverlay returned.
func (m *bsonMasker) maskScalar(name, path string, typ byte, value []byte) ([]byte, error) {
	cols := []mask.Column{{Name: name, Path: path, ObjectID: m.curObjectID, Text: true, FreeText: false, TypeKind: bsonTypeKind[typ]}}
	out, err := m.masker.MaskRow(m.ctx, cols, [][]byte{append([]byte(nil), value...)})
	if err != nil {
		return value, err
	}
	if len(out) != 1 || out[0] == nil || bytes.Equal(out[0], value) {
		return value, nil
	}
	return zeroValueBSON(typ), nil
}

// maskString runs a single BSON string value (int32 length + bytes + NUL) through the masker. A
// masker failure (e.g. mask.ErrMaskerUnavailable in strict mode) propagates as an error so the
// caller aborts the connection instead of forwarding the raw value; a malformed BSON length or a
// clean "nothing to mask" result is not an error.
func (m *bsonMasker) maskString(name, path string, value []byte) ([]byte, error) {
	if len(value) < 5 {
		return value, nil
	}
	l := int(binary.LittleEndian.Uint32(value))
	if l < 1 || 4+l > len(value) {
		return value, nil
	}
	s := value[4 : 4+l-1] // exclude trailing NUL
	if m.collector != nil && m.curObjectID != "" {
		m.collector.Observe(m.curObjectID, path, string(s))
	}
	cols := []mask.Column{{Name: name, Path: path, ObjectID: m.curObjectID, Text: true, FreeText: true}}
	out, err := m.masker.MaskRow(m.ctx, cols, [][]byte{append([]byte(nil), s...)})
	if err != nil {
		return value, err
	}
	if len(out) != 1 || out[0] == nil || bytes.Equal(out[0], s) {
		return value, nil
	}
	nv := make([]byte, 4, 4+len(out[0])+1)
	binary.LittleEndian.PutUint32(nv, uint32(len(out[0])+1))
	nv = append(nv, out[0]...)
	nv = append(nv, 0x00)
	return nv, nil
}
