// Package mongo implements the MongoDB wire protocol (OP_MSG / BSON) as a masking proxy.
//
// Shape (mirrors the postgres/mysql engines): client->server requests are always forwarded
// byte-identical (never mutated), but are also read-only parsed to learn the target
// database/collection of each command (find/aggregate/getMore/...), keyed by the message's
// requestID; server->client OP_MSG replies are parsed and the string field values inside query
// result batches (cursor.firstBatch / cursor.nextBatch, and OP_MSG document-sequence sections) are
// run through the masker before the message is re-framed, using the matching request's
// database/collection (correlated via the reply's responseTo header field) to set
// mask.Column.ObjectID/Path for the path-scoped masking layer. A request that fails to parse (or
// whose reply never arrives) simply yields an empty ObjectID for that response, same as if
// identity resolution weren't attempted at all — every masking layer already treats that as "no
// label available," not as an error.
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
	"sync"

	"github.com/curlix-io/skybridge/internal/mask"
	"github.com/curlix-io/skybridge/internal/wire"
)

const (
	opMsg               = 2013
	headerLen           = 16
	flagChecksumPresent = 1 << 0
	maxMessageBytes     = 64 << 20 // generous cap (mongod default maxMessageSizeBytes is 48 MiB)
)

// Engine is the MongoDB wire-proxy engine.
type Engine struct {
	// orgID scopes mask.Column.ObjectID for path-/table-aware masking labels (see
	// internal/pathlabel). Empty disables that scoping without otherwise affecting masking.
	orgID string
}

// New returns a MongoDB engine.
func New() *Engine { return &Engine{} }

// WithOrgID returns a copy of the engine that scopes mask.Column.ObjectID to orgID for path-/
// table-aware masking labels (see internal/pathlabel). Call with "" to leave scoping disabled.
func (e *Engine) WithOrgID(orgID string) *Engine {
	c := *e
	c.orgID = orgID
	return &c
}

// Name implements wire.Engine.
func (*Engine) Name() string { return "mongodb" }

// Proxy implements wire.Engine.
func (e *Engine) Proxy(ctx context.Context, client, upstream net.Conn, masker mask.Masker, recorder wire.Recorder) error {
	if masker == nil {
		masker = mask.Noop{}
	}
	if recorder == nil {
		recorder = wire.NoopRecorder{}
	}
	tracker := newRequestTracker()
	errc := make(chan error, 2)
	go func() {
		errc <- proxyClientRequests(bufio.NewReaderSize(client, 1<<16), upstream, recorder, tracker)
	}()
	go func() {
		errc <- maskServer(ctx, bufio.NewReaderSize(upstream, 1<<16), client, masker, recorder, tracker, e.orgID)
	}()
	err := <-errc
	_ = client.Close()
	_ = upstream.Close()
	<-errc
	if errors.Is(err, io.EOF) || errors.Is(err, net.ErrClosed) {
		return nil
	}
	return err
}

// proxyClientRequests forwards client->server messages byte-identical to upstream, while also
// read-only parsing each one (best-effort) to learn its target database/collection for tracker —
// a parse failure never affects forwarding, only leaves that request's eventual reply with no
// resolved identity.
func proxyClientRequests(r *bufio.Reader, w io.Writer, recorder wire.Recorder, tracker *requestTracker) error {
	for {
		msg, err := readMessage(r)
		if err != nil {
			return err
		}
		recorder.RecordInput(msg)
		tracker.observe(msg)
		if _, err := w.Write(msg); err != nil {
			return err
		}
	}
}

func maskServer(ctx context.Context, r *bufio.Reader, w io.Writer, masker mask.Masker, recorder wire.Recorder, tracker *requestTracker, orgID string) error {
	bm := &bsonMasker{ctx: ctx, masker: masker, recorder: recorder, tracker: tracker, orgID: orgID}
	for {
		msg, err := readMessage(r)
		if err != nil {
			return err
		}
		out, err := transformMessage(bm, msg)
		if err != nil {
			return err
		}
		if _, err := w.Write(out); err != nil {
			return err
		}
	}
}

// maxTrackedRequests bounds requestTracker's in-memory map so a client that issues requests faster
// than it reads replies (or disconnects mid-cursor) cannot grow it without limit (CLAUDE.md's
// no-unbounded-growth rule, mirrored from remotestore's maxPendingLabels).
const maxTrackedRequests = 4096

// requestTracker correlates a request's database/collection (learned by parsing the client's
// find/aggregate/getMore command as it passes through, read-only) with its eventual reply, via the
// wire protocol's requestID/responseTo header fields. Safe for concurrent use: observe runs on the
// client->server goroutine, resolve on the server->client goroutine.
type requestTracker struct {
	mu      sync.Mutex
	pending map[int32]collectionInfo
}

type collectionInfo struct {
	db         string
	collection string
}

func newRequestTracker() *requestTracker {
	return &requestTracker{pending: make(map[int32]collectionInfo)}
}

// observe best-effort parses a client->server message and records its target database/collection,
// keyed by requestID, for later resolution by resolve. Any parse failure (or a command this engine
// doesn't track, e.g. "hello"/"ismaster") is silently skipped — the eventual reply simply resolves
// to no ObjectID, exactly as if identity tracking weren't attempted at all.
func (t *requestTracker) observe(msg []byte) {
	if len(msg) < headerLen {
		return
	}
	if int32(binary.LittleEndian.Uint32(msg[12:16])) != opMsg {
		return
	}
	requestID := int32(binary.LittleEndian.Uint32(msg[4:8]))
	info, ok := parseCommandInfo(msg)
	if !ok {
		return
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	if _, exists := t.pending[requestID]; !exists && len(t.pending) >= maxTrackedRequests {
		// Map iteration order is randomized in Go, so this evicts an arbitrary entry rather than
		// the oldest — acceptable here since this is purely a size cap against a pathological
		// client, not an LRU cache whose eviction policy affects correctness.
		for k := range t.pending {
			delete(t.pending, k)
			break
		}
	}
	t.pending[requestID] = info
}

// resolve looks up and consumes the tracked database/collection for responseTo (the requestID of
// the request this reply answers). Consumed on read so a connection issuing many requests without
// tracked replies (e.g. writes) doesn't leak entries.
func (t *requestTracker) resolve(responseTo int32) (collectionInfo, bool) {
	t.mu.Lock()
	defer t.mu.Unlock()
	info, ok := t.pending[responseTo]
	if ok {
		delete(t.pending, responseTo)
	}
	return info, ok
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

// transformMessage masks an OP_MSG reply. On any non-OP_MSG opcode or benign parse problem it
// returns the original bytes unchanged. A masker failure (mask.ErrMaskerUnavailable in strict
// mode) is returned as an error instead, so the caller aborts rather than forwarding raw content.
func transformMessage(bm *bsonMasker, msg []byte) ([]byte, error) {
	if len(msg) < headerLen+4 {
		return msg, nil
	}
	if int(binary.LittleEndian.Uint32(msg[12:16])) != opMsg {
		return msg, nil
	}
	responseTo := int32(binary.LittleEndian.Uint32(msg[8:12]))
	bm.resolveObjectID(responseTo)
	flags := binary.LittleEndian.Uint32(msg[16:20])

	end := len(msg)
	if flags&flagChecksumPresent != 0 {
		if end-4 < 20 {
			return msg, nil
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
				return msg, nil
			}
			dl := int(binary.LittleEndian.Uint32(msg[off+1 : off+5]))
			if dl < 5 || off+1+dl > end {
				return msg, nil
			}
			doc := msg[off+1 : off+1+dl]
			nd, err := bm.body(doc)
			if err != nil {
				if errors.Is(err, mask.ErrMaskerUnavailable) {
					return nil, err
				}
				return msg, nil
			}
			if !bytesEqual(nd, doc) {
				changed = true
			}
			sections = append(sections, 0)
			sections = append(sections, nd...)
			off += 1 + dl
		case 1: // document sequence
			if off+1+4 > end {
				return msg, nil
			}
			ss := int(binary.LittleEndian.Uint32(msg[off+1 : off+5]))
			if ss < 4 || off+1+ss > end {
				return msg, nil
			}
			sec := msg[off+1 : off+1+ss]
			ns, ch, err := bm.sequence(sec)
			if err != nil {
				if errors.Is(err, mask.ErrMaskerUnavailable) {
					return nil, err
				}
				return msg, nil
			}
			if ch {
				changed = true
			}
			sections = append(sections, 1)
			sections = append(sections, ns...)
			off += 1 + ss
		default:
			return msg, nil
		}
	}

	if !changed {
		return msg, nil
	}

	out := make([]byte, 0, headerLen+4+len(sections))
	out = append(out, msg[:headerLen]...)
	var fb [4]byte
	binary.LittleEndian.PutUint32(fb[:], flags&^flagChecksumPresent)
	out = append(out, fb[:]...)
	out = append(out, sections...)
	binary.LittleEndian.PutUint32(out[0:4], uint32(len(out)))
	return out, nil
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
		nd, err := m.result(doc, "")
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
