// Package mongo implements the MongoDB wire protocol (OP_MSG / BSON) as a masking proxy.
//
// Shape (mirrors the postgres/mysql engines): client->server requests are forwarded verbatim;
// server->client OP_MSG replies are parsed and the string field values inside query result batches
// (cursor.firstBatch / cursor.nextBatch, and OP_MSG document-sequence sections) are run through the
// masker before the message is re-framed. BSON has no column metadata, so masking relies on the
// remote (content) masker plus the field-name overlay.
//
// Safe by construction: only OP_MSG result batches are descended into. Handshake/auth/protocol
// fields are never touched, and any parse error falls back to forwarding the original bytes. When a
// message is modified its optional CRC32C checksum is dropped (the checksumPresent flag is cleared),
// which is always valid since the checksum is optional.
//
// Limitations: legacy OP_REPLY (opcode 1) responses are passed through unmasked; modern mongosh and
// drivers use OP_MSG.
package mongo

import (
	"bufio"
	"context"
	"encoding/binary"
	"errors"
	"io"
	"net"

	"github.com/curlix-io/skybridge/internal/mask"
)

const (
	opMsg               = 2013
	headerLen           = 16
	flagChecksumPresent = 1 << 0
	maxMessageBytes     = 64 << 20 // generous cap (mongod default maxMessageSizeBytes is 48 MiB)
)

// Engine is the MongoDB wire-proxy engine.
type Engine struct{}

// New returns a MongoDB engine.
func New() *Engine { return &Engine{} }

// Name implements wire.Engine.
func (*Engine) Name() string { return "mongodb" }

// Proxy implements wire.Engine.
func (*Engine) Proxy(ctx context.Context, client, upstream net.Conn, masker mask.Masker) error {
	if masker == nil {
		masker = mask.Noop{}
	}
	errc := make(chan error, 2)
	go func() { _, e := io.Copy(upstream, client); errc <- e }() // requests verbatim
	go func() { errc <- maskServer(ctx, bufio.NewReaderSize(upstream, 1<<16), client, masker) }()
	err := <-errc
	_ = client.Close()
	_ = upstream.Close()
	<-errc
	if errors.Is(err, io.EOF) || errors.Is(err, net.ErrClosed) {
		return nil
	}
	return err
}

func maskServer(ctx context.Context, r *bufio.Reader, w io.Writer, masker mask.Masker) error {
	bm := &bsonMasker{ctx: ctx, masker: masker}
	for {
		msg, err := readMessage(r)
		if err != nil {
			return err
		}
		if _, err := w.Write(transformMessage(bm, msg)); err != nil {
			return err
		}
	}
}

// readMessage reads one complete wire message (header + body) framed by its leading int32 length.
func readMessage(r *bufio.Reader) ([]byte, error) {
	var hdr [4]byte
	if _, err := io.ReadFull(r, hdr[:]); err != nil {
		return nil, err
	}
	total := int(binary.LittleEndian.Uint32(hdr[:]))
	if total < headerLen || total > maxMessageBytes {
		return nil, errors.New("mongo: implausible message length")
	}
	msg := make([]byte, total)
	copy(msg, hdr[:])
	if _, err := io.ReadFull(r, msg[4:]); err != nil {
		return nil, err
	}
	return msg, nil
}

// transformMessage masks an OP_MSG reply. On any non-OP_MSG opcode or parse problem it returns the
// original bytes unchanged.
func transformMessage(bm *bsonMasker, msg []byte) []byte {
	if len(msg) < headerLen+4 {
		return msg
	}
	if int(binary.LittleEndian.Uint32(msg[12:16])) != opMsg {
		return msg
	}
	flags := binary.LittleEndian.Uint32(msg[16:20])

	end := len(msg)
	if flags&flagChecksumPresent != 0 {
		if end-4 < 20 {
			return msg
		}
		end -= 4 // strip trailing CRC32C; we will clear the flag below
	}

	sections := make([]byte, 0, end-20)
	changed := false
	off := 20
	for off < end {
		switch msg[off] {
		case 0: // body document
			if off+1+4 > end {
				return msg
			}
			dl := int(binary.LittleEndian.Uint32(msg[off+1 : off+5]))
			if dl < 5 || off+1+dl > end {
				return msg
			}
			doc := msg[off+1 : off+1+dl]
			nd, err := bm.body(doc)
			if err != nil {
				return msg
			}
			if !bytesEqual(nd, doc) {
				changed = true
			}
			sections = append(sections, 0)
			sections = append(sections, nd...)
			off += 1 + dl
		case 1: // document sequence
			if off+1+4 > end {
				return msg
			}
			ss := int(binary.LittleEndian.Uint32(msg[off+1 : off+5]))
			if ss < 4 || off+1+ss > end {
				return msg
			}
			sec := msg[off+1 : off+1+ss]
			ns, ch, err := bm.sequence(sec)
			if err != nil {
				return msg
			}
			if ch {
				changed = true
			}
			sections = append(sections, 1)
			sections = append(sections, ns...)
			off += 1 + ss
		default:
			return msg
		}
	}

	if !changed {
		return msg
	}

	out := make([]byte, 0, headerLen+4+len(sections))
	out = append(out, msg[:headerLen]...)
	var fb [4]byte
	binary.LittleEndian.PutUint32(fb[:], flags&^flagChecksumPresent)
	out = append(out, fb[:]...)
	out = append(out, sections...)
	binary.LittleEndian.PutUint32(out[0:4], uint32(len(out)))
	return out
}

// sequence masks every document in an OP_MSG document-sequence section. sec is [int32 size][cstring
// identifier][doc...]; size == len(sec).
func (m *bsonMasker) sequence(sec []byte) ([]byte, bool, error) {
	if len(sec) < 5 {
		return nil, false, errBadBSON
	}
	idEnd := indexByte(sec[4:])
	if idEnd < 0 {
		return nil, false, errBadBSON
	}
	idEnd += 4
	prefix := sec[:idEnd+1] // size + identifier (incl NUL)
	rest := sec[idEnd+1:]

	docs := make([]byte, 0, len(rest))
	changed := false
	off := 0
	for off < len(rest) {
		if off+4 > len(rest) {
			return nil, false, errBadBSON
		}
		dl := int(binary.LittleEndian.Uint32(rest[off : off+4]))
		if dl < 5 || off+dl > len(rest) {
			return nil, false, errBadBSON
		}
		doc := rest[off : off+dl]
		nd, err := m.result(doc)
		if err != nil {
			return nil, false, err
		}
		if !bytesEqual(nd, doc) {
			changed = true
		}
		docs = append(docs, nd...)
		off += dl
	}

	out := make([]byte, 0, len(prefix)+len(docs))
	out = append(out, prefix...)
	out = append(out, docs...)
	binary.LittleEndian.PutUint32(out[0:4], uint32(len(out)))
	return out, changed, nil
}

func indexByte(b []byte) int {
	for i := range b {
		if b[i] == 0x00 {
			return i
		}
	}
	return -1
}

func bytesEqual(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}
