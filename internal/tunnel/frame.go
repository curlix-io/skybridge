// Package tunnel is the egress-only data-plane transport between a Skybridge agent and the relay
// gateway. The agent dials OUT to the gateway and holds a single long-lived connection; the gateway
// multiplexes many native-client sessions over it as logical streams. Masking always happens at the
// agent (it runs the wire engine against the upstream DB), so the gateway only ever relays
// already-masked bytes — raw data never leaves the egress network.
//
// This is the versioned wire contract for that boundary (see CONTRACT.md). The frame header is fixed
// and version-tagged so it can evolve compatibly.
//
// Frame layout (big-endian):
//
//	magic   2  'S' 'B'
//	version 1
//	type    1  (control | open | data | close)
//	flags   1  (reserved, 0)
//	connID  8  logical stream id (0 for control frames)
//	length  4  payload length
//	payload length bytes
package tunnel

import (
	"encoding/binary"
	"errors"
	"io"
)

const (
	magic0  = 0x53 // 'S'
	magic1  = 0x42 // 'B'
	version = 1

	headerLen = 17

	// MaxPayload bounds a single frame's payload. Stream writes are chunked to this size; control
	// messages must fit within it (they are small JSON blobs).
	MaxPayload = 1 << 15 // 32 KiB
)

type frameType byte

const (
	frameControl frameType = 0x01
	frameOpen    frameType = 0x10
	frameData    frameType = 0x12
	frameClose   frameType = 0x13
)

var (
	errBadMagic    = errors.New("tunnel: bad frame magic")
	errBadVersion  = errors.New("tunnel: unsupported frame version")
	errFrameTooBig = errors.New("tunnel: frame payload exceeds maximum")
)

type frame struct {
	typ     frameType
	connID  uint64
	payload []byte
}

func writeFrameTo(w io.Writer, typ frameType, connID uint64, payload []byte) error {
	if len(payload) > MaxPayload {
		return errFrameTooBig
	}
	var h [headerLen]byte
	h[0] = magic0
	h[1] = magic1
	h[2] = version
	h[3] = byte(typ)
	h[4] = 0
	binary.BigEndian.PutUint64(h[5:13], connID)
	binary.BigEndian.PutUint32(h[13:17], uint32(len(payload)))
	if _, err := w.Write(h[:]); err != nil {
		return err
	}
	if len(payload) > 0 {
		if _, err := w.Write(payload); err != nil {
			return err
		}
	}
	return nil
}

func readFrame(r io.Reader) (frame, error) {
	var h [headerLen]byte
	if _, err := io.ReadFull(r, h[:]); err != nil {
		return frame{}, err
	}
	if h[0] != magic0 || h[1] != magic1 {
		return frame{}, errBadMagic
	}
	if h[2] != version {
		return frame{}, errBadVersion
	}
	n := binary.BigEndian.Uint32(h[13:17])
	if n > MaxPayload {
		return frame{}, errFrameTooBig
	}
	p := make([]byte, n)
	if _, err := io.ReadFull(r, p); err != nil {
		return frame{}, err
	}
	return frame{typ: frameType(h[3]), connID: binary.BigEndian.Uint64(h[5:13]), payload: p}, nil
}
