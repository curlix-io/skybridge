package tunnel

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"runtime/debug"
	"sync"
	"time"
)

// ErrSessionClosed is returned once the underlying connection is gone.
var ErrSessionClosed = errors.New("tunnel: session closed")

// errStreamBufferOverflow fails a stream whose peer has sent more data than the consumer has
// drained, past maxStreamBufferBytes — see Stream.deliver.
var errStreamBufferOverflow = errors.New("tunnel: stream buffer exceeded limit")

// IdleTimeout bounds how long the read loop waits for ANY frame (data or heartbeat) before treating
// the peer as dead. Both sides must send heartbeats well inside this window (see agent.go's
// heartbeatLoop and the gateway's mirror of it) — otherwise an idle-but-healthy link with no client
// traffic would be torn down. Ungraceful peer death (ECS task killed, no FIN) leaves a plain
// io.ReadFull blocked forever with nothing to signal it; this deadline is what actually detects that.
const IdleTimeout = 45 * time.Second

// maxStreams bounds how many concurrently open logical streams one Session tracks. Without this, a
// peer sending unlimited "open" frames grows Session.streams (one *Stream + buffer per entry)
// without limit. Set well above any real deployment's per-org concurrency — one Session serves one
// org's traffic (see internal/gateway's default SKYBRIDGE_GW_ORG_MAX_CONCURRENT_CLIENTS=1000) — so
// this is a safety backstop against a malicious/compromised peer, not an operational ceiling.
// A var, not a const, so tests can temporarily lower it rather than opening thousands of real
// streams to exercise the limit.
var maxStreams = 10000

// maxStreamBufferBytes bounds how many undelivered bytes Stream.deliver will buffer for one stream
// before the consumer (the wire engine reading from it) catches up. At 32 KiB/frame (MaxPayload)
// this is ~128 frames of slack — generous for ordinary scheduling jitter, but without it a peer
// that keeps sending data for a stream nobody is draining (or a stalled consumer) could grow that
// one stream's buffer without limit.
const maxStreamBufferBytes = 4 << 20

// Session multiplexes logical streams and a control channel over one net.Conn.
type Session struct {
	conn net.Conn

	wmu sync.Mutex // serializes frame writes to conn

	mu      sync.Mutex
	streams map[uint64]*Stream
	nextID  uint64

	accept    chan *Stream
	controlCh chan Control

	closeOnce sync.Once
	closed    chan struct{}
	err       error
}

// Client wraps a connection initiated by the dialer (the agent side).
func Client(conn net.Conn) *Session { return newSession(conn, true) }

// Server wraps an accepted connection (the gateway side).
func Server(conn net.Conn) *Session { return newSession(conn, false) }

func newSession(conn net.Conn, isClient bool) *Session {
	s := &Session{
		conn:      conn,
		streams:   make(map[uint64]*Stream),
		accept:    make(chan *Stream, 64),
		controlCh: make(chan Control, 16),
		closed:    make(chan struct{}),
	}
	if isClient {
		s.nextID = 1 // client opens odd ids
	} else {
		s.nextID = 2 // server opens even ids
	}
	go s.runReadLoop()
	return s
}

// runReadLoop wraps readLoop with panic recovery: a malformed/adversarial frame hitting an
// unhandled parsing edge case must only end this one session, never crash the whole agent/gateway
// process and take down every other tenant's session sharing it. Mirrors internal/wire.SafeGo's
// reasoning; kept local rather than importing internal/wire, which would pull this deliberately
// stdlib-only package into wire's dependency graph for a few lines of shared logic.
func (s *Session) runReadLoop() {
	defer func() {
		if r := recover(); r != nil {
			s.closeWithErr(fmt.Errorf("tunnel: recovered from panic in read loop: %v\n%s", r, debug.Stack()))
		}
	}()
	s.readLoop()
}

// Open creates a new outbound logical stream carrying meta in its OPEN frame.
func (s *Session) Open(meta []byte) (*Stream, error) {
	st, err := func() (*Stream, error) {
		s.mu.Lock()
		defer s.mu.Unlock()
		select {
		case <-s.closed:
			return nil, s.errOrClosed()
		default:
		}
		id := s.nextID
		s.nextID += 2
		st := newStream(s, id, meta)
		s.streams[id] = st
		return st, nil
	}()
	if err != nil {
		return nil, err
	}

	if err := s.writeFrame(frameOpen, st.id, meta); err != nil {
		s.removeStream(st.id)
		return nil, err
	}
	return st, nil
}

// Accept returns the next inbound stream opened by the peer.
func (s *Session) Accept() (*Stream, error) {
	select {
	case st := <-s.accept:
		return st, nil
	case <-s.closed:
		return nil, s.errOrClosed()
	}
}

// SendControl writes a control message to the peer.
func (s *Session) SendControl(c Control) error {
	return s.writeFrame(frameControl, 0, c.encode())
}

// NextControl blocks for the next inbound control message.
func (s *Session) NextControl() (Control, error) {
	select {
	case c := <-s.controlCh:
		return c, nil
	case <-s.closed:
		return Control{}, s.errOrClosed()
	}
}

// Closed returns a channel closed when the session ends.
func (s *Session) Closed() <-chan struct{} { return s.closed }

// Close tears down the session and underlying connection.
func (s *Session) Close() error {
	s.closeWithErr(ErrSessionClosed)
	return nil
}

func (s *Session) errOrClosed() error {
	if s.err != nil {
		return s.err
	}
	return ErrSessionClosed
}

func (s *Session) readLoop() {
	for {
		// Reset before every frame: a healthy peer sends at least a heartbeat within IdleTimeout, so
		// this only fires when nothing at all — not even a heartbeat — has arrived in that window,
		// which is exactly the signature of an ungracefully-killed peer (half-open socket, no FIN).
		_ = s.conn.SetReadDeadline(time.Now().Add(IdleTimeout))
		f, err := readFrame(s.conn)
		if err != nil {
			s.closeWithErr(err)
			return
		}
		switch f.typ {
		case frameControl:
			c, err := decodeControl(f.payload)
			if err != nil {
				continue
			}
			select {
			case s.controlCh <- c:
			case <-s.closed:
				return
			default:
				// control channel full (slow consumer); drop liveness-style messages
			}
		case frameOpen:
			// A defer-based unlock (rather than the explicit Lock/Unlock pairs this package used
			// before) matters here specifically: if anything between Lock and Unlock ever panics,
			// runReadLoop's recover would otherwise re-Lock this same mutex while it's still held
			// from the panicking call — a deadlock, not a clean recovery. defer guarantees the
			// unlock happens during the panic unwind too.
			st, ok := func() (*Stream, bool) {
				s.mu.Lock()
				defer s.mu.Unlock()
				if len(s.streams) >= maxStreams {
					return nil, false
				}
				st := newStream(s, f.connID, f.payload)
				s.streams[f.connID] = st
				return st, true
			}()
			if !ok {
				// Drop the open silently: the peer's Open() already returned successfully on its
				// side (it doesn't wait for an ack), so there's no ack to send. Any data frames
				// that follow for this connID find no matching entry in s.streams and are dropped
				// the same way (see the frameData case below) — safe, if not graceful; this path
				// only triggers against a malicious/compromised peer or a real bug, never in
				// normal operation given maxStreams' size.
				continue
			}
			select {
			case s.accept <- st:
			case <-s.closed:
				return
			}
		case frameData:
			st := func() *Stream {
				s.mu.Lock()
				defer s.mu.Unlock()
				return s.streams[f.connID]
			}()
			if st != nil {
				st.deliver(f.payload)
			}
		case frameClose:
			st := func() *Stream {
				s.mu.Lock()
				defer s.mu.Unlock()
				st := s.streams[f.connID]
				delete(s.streams, f.connID)
				return st
			}()
			if st != nil {
				st.remoteClose()
			}
		}
	}
}

func (s *Session) writeFrame(typ frameType, id uint64, payload []byte) error {
	select {
	case <-s.closed:
		return s.errOrClosed()
	default:
	}
	s.wmu.Lock()
	defer s.wmu.Unlock()
	return writeFrameTo(s.conn, typ, id, payload)
}

func (s *Session) writeData(id uint64, p []byte) (int, error) {
	total := 0
	for len(p) > 0 {
		n := len(p)
		if n > MaxPayload {
			n = MaxPayload
		}
		if err := s.writeFrame(frameData, id, p[:n]); err != nil {
			return total, err
		}
		p = p[n:]
		total += n
	}
	return total, nil
}

func (s *Session) removeStream(id uint64) {
	s.mu.Lock()
	delete(s.streams, id)
	s.mu.Unlock()
}

func (s *Session) closeWithErr(err error) {
	s.closeOnce.Do(func() {
		s.err = err
		close(s.closed)
		if s.conn != nil {
			_ = s.conn.Close()
		}
		func() {
			s.mu.Lock()
			defer s.mu.Unlock()
			for _, st := range s.streams {
				st.fail(err)
			}
			s.streams = make(map[uint64]*Stream)
		}()
	})
}

// Stream is a logical, bidirectional, reliable byte stream multiplexed over a Session. It implements
// net.Conn so the wire engines can use it as the "client" connection unchanged.
type Stream struct {
	id   uint64
	sess *Session
	meta []byte

	mu           sync.Mutex
	cond         *sync.Cond
	buf          bytes.Buffer
	localClosed  bool
	remoteClosed bool
	err          error

	readDeadline time.Time
	rdTimer      *time.Timer
}

func newStream(sess *Session, id uint64, meta []byte) *Stream {
	st := &Stream{id: id, sess: sess, meta: meta}
	st.cond = sync.NewCond(&st.mu)
	return st
}

// Meta returns the OPEN-frame metadata the stream was created with.
func (s *Stream) Meta() []byte { return s.meta }

func (s *Stream) deliver(p []byte) {
	s.mu.Lock()
	if !s.localClosed && !s.remoteClosed && s.err == nil {
		if s.buf.Len()+len(p) > maxStreamBufferBytes {
			// Fail this one stream rather than growing its buffer without limit or silently
			// dropping/truncating bytes (which would corrupt the client's data) — same "abort
			// rather than corrupt" contract the wire engines use for oversized messages.
			s.err = errStreamBufferOverflow
			s.cond.Broadcast()
			s.mu.Unlock()
			return
		}
		s.buf.Write(p)
		s.cond.Broadcast()
	}
	s.mu.Unlock()
}

func (s *Stream) remoteClose() {
	s.mu.Lock()
	s.remoteClosed = true
	s.cond.Broadcast()
	s.mu.Unlock()
}

func (s *Stream) fail(err error) {
	s.mu.Lock()
	if s.err == nil {
		s.err = err
	}
	s.cond.Broadcast()
	s.mu.Unlock()
}

// Read implements net.Conn.
func (s *Stream) Read(p []byte) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for s.buf.Len() == 0 {
		if s.err != nil {
			return 0, s.err
		}
		if !s.readDeadline.IsZero() && !time.Now().Before(s.readDeadline) {
			return 0, os.ErrDeadlineExceeded
		}
		if s.remoteClosed {
			return 0, io.EOF
		}
		if s.localClosed {
			return 0, net.ErrClosed
		}
		s.cond.Wait()
	}
	return s.buf.Read(p)
}

// Write implements net.Conn.
func (s *Stream) Write(p []byte) (int, error) {
	s.mu.Lock()
	closed := s.localClosed || s.err != nil
	s.mu.Unlock()
	if closed {
		return 0, net.ErrClosed
	}
	return s.sess.writeData(s.id, p)
}

// Close implements net.Conn. It signals the peer with a CLOSE frame.
func (s *Stream) Close() error {
	s.mu.Lock()
	if s.localClosed {
		s.mu.Unlock()
		return nil
	}
	s.localClosed = true
	if s.rdTimer != nil {
		s.rdTimer.Stop()
	}
	s.cond.Broadcast()
	s.mu.Unlock()
	s.sess.removeStream(s.id)
	return s.sess.writeFrame(frameClose, s.id, nil)
}

// LocalAddr implements net.Conn.
func (s *Stream) LocalAddr() net.Addr { return streamAddr(s.id) }

// RemoteAddr implements net.Conn.
func (s *Stream) RemoteAddr() net.Addr { return streamAddr(s.id) }

// SetDeadline implements net.Conn.
func (s *Stream) SetDeadline(t time.Time) error { return s.SetReadDeadline(t) }

// SetReadDeadline implements net.Conn.
func (s *Stream) SetReadDeadline(t time.Time) error {
	s.mu.Lock()
	s.readDeadline = t
	if s.rdTimer != nil {
		s.rdTimer.Stop()
		s.rdTimer = nil
	}
	if !t.IsZero() {
		s.rdTimer = time.AfterFunc(time.Until(t), func() {
			s.mu.Lock()
			s.cond.Broadcast()
			s.mu.Unlock()
		})
	}
	s.mu.Unlock()
	return nil
}

// SetWriteDeadline implements net.Conn. Writes are immediate frame emits; deadlines are a no-op
// because the underlying conn is shared by all streams.
func (s *Stream) SetWriteDeadline(time.Time) error { return nil }

type streamAddr uint64

func (streamAddr) Network() string { return "skybridge-tunnel" }
func (a streamAddr) String() string {
	return "stream"
}
