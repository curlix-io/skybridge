package tunnel

import (
	"bytes"
	"errors"
	"io"
	"net"
	"os"
	"sync"
	"time"
)

// ErrSessionClosed is returned once the underlying connection is gone.
var ErrSessionClosed = errors.New("tunnel: session closed")

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
	go s.readLoop()
	return s
}

// Open creates a new outbound logical stream carrying meta in its OPEN frame.
func (s *Session) Open(meta []byte) (*Stream, error) {
	s.mu.Lock()
	select {
	case <-s.closed:
		s.mu.Unlock()
		return nil, s.errOrClosed()
	default:
	}
	id := s.nextID
	s.nextID += 2
	st := newStream(s, id, meta)
	s.streams[id] = st
	s.mu.Unlock()

	if err := s.writeFrame(frameOpen, id, meta); err != nil {
		s.removeStream(id)
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
			st := newStream(s, f.connID, f.payload)
			s.mu.Lock()
			s.streams[f.connID] = st
			s.mu.Unlock()
			select {
			case s.accept <- st:
			case <-s.closed:
				return
			}
		case frameData:
			s.mu.Lock()
			st := s.streams[f.connID]
			s.mu.Unlock()
			if st != nil {
				st.deliver(f.payload)
			}
		case frameClose:
			s.mu.Lock()
			st := s.streams[f.connID]
			delete(s.streams, f.connID)
			s.mu.Unlock()
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
		_ = s.conn.Close()
		s.mu.Lock()
		for _, st := range s.streams {
			st.fail(err)
		}
		s.streams = make(map[uint64]*Stream)
		s.mu.Unlock()
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
