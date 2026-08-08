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
		masked, err := m.result(value)
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

// result masks every string field in a result document, recursing into nested docs/arrays.
func (m *bsonMasker) result(doc []byte) ([]byte, error) {
	return rewriteDoc(doc, func(typ byte, name string, value []byte) ([]byte, error) {
		switch typ {
		case bsonString:
			return m.maskString(name, value)
		case bsonDoc, bsonArray:
			return m.result(value)
		default:
			return value, nil
		}
	})
}

// maskString runs a single BSON string value (int32 length + bytes + NUL) through the masker. A
// masker failure (e.g. mask.ErrMaskerUnavailable in strict mode) propagates as an error so the
// caller aborts the connection instead of forwarding the raw value; a malformed BSON length or a
// clean "nothing to mask" result is not an error.
func (m *bsonMasker) maskString(name string, value []byte) ([]byte, error) {
	if len(value) < 5 {
		return value, nil
	}
	l := int(binary.LittleEndian.Uint32(value))
	if l < 1 || 4+l > len(value) {
		return value, nil
	}
	s := value[4 : 4+l-1] // exclude trailing NUL
	cols := []mask.Column{{Name: name, Text: true}}
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
