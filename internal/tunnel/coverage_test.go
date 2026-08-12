package tunnel

import (
	"bytes"
	"errors"
	"io"
	"net"
	"testing"
	"time"
)

// TestFrameWriteRejectsOversizePayload exercises writeFrameTo's MaxPayload guard.
func TestFrameWriteRejectsOversizePayload(t *testing.T) {
	var buf bytes.Buffer
	big := make([]byte, MaxPayload+1)
	if err := writeFrameTo(&buf, frameData, 1, big); !errors.Is(err, errFrameTooBig) {
		t.Fatalf("expected errFrameTooBig, got %v", err)
	}
}

// TestFrameWriteRejectsWriterErrorOnHeader ensures a header-write failure surfaces the writer's
// error rather than silently succeeding.
func TestFrameWriteRejectsWriterErrorOnHeader(t *testing.T) {
	w := &failingWriter{failAfter: 0}
	if err := writeFrameTo(w, frameData, 1, []byte("x")); err == nil {
		t.Fatal("expected error when header write fails")
	}
}

// TestFrameWriteRejectsWriterErrorOnPayload exercises the payload-write error branch: the header
// write succeeds (first call) but the payload write (second call) fails.
func TestFrameWriteRejectsWriterErrorOnPayload(t *testing.T) {
	w := &failingWriter{failAfter: 1}
	if err := writeFrameTo(w, frameData, 1, []byte("payload")); err == nil {
		t.Fatal("expected error when payload write fails")
	}
}

type failingWriter struct {
	calls     int
	failAfter int
}

func (f *failingWriter) Write(p []byte) (int, error) {
	if f.calls >= f.failAfter {
		f.calls++
		return 0, errors.New("boom")
	}
	f.calls++
	return len(p), nil
}

// TestFrameReadRejectsUnsupportedVersion exercises readFrame's version check.
func TestFrameReadRejectsUnsupportedVersion(t *testing.T) {
	var h [headerLen]byte
	h[0], h[1] = magic0, magic1
	h[2] = version + 1
	if _, err := readFrame(bytes.NewReader(h[:])); !errors.Is(err, errBadVersion) {
		t.Fatalf("expected errBadVersion, got %v", err)
	}
}

// TestFrameReadRejectsOversizeLength exercises readFrame's MaxPayload guard on the declared length.
func TestFrameReadRejectsOversizeLength(t *testing.T) {
	var h [headerLen]byte
	h[0], h[1] = magic0, magic1
	h[2] = version
	// length field is big-endian at h[13:17]; set it above MaxPayload.
	h[13] = 0xFF
	h[14] = 0xFF
	h[15] = 0xFF
	h[16] = 0xFF
	if _, err := readFrame(bytes.NewReader(h[:])); !errors.Is(err, errFrameTooBig) {
		t.Fatalf("expected errFrameTooBig, got %v", err)
	}
}

// TestFrameReadRejectsTruncatedPayload exercises the io.ReadFull failure path when the header
// declares more payload bytes than are actually present.
func TestFrameReadRejectsTruncatedPayload(t *testing.T) {
	var buf bytes.Buffer
	if err := writeFrameTo(&buf, frameData, 1, []byte("hello world")); err != nil {
		t.Fatal(err)
	}
	full := buf.Bytes()
	truncated := full[:len(full)-3] // chop off part of the payload
	if _, err := readFrame(bytes.NewReader(truncated)); err == nil {
		t.Fatal("expected error on truncated payload")
	}
}

// TestOpenAfterCloseReturnsError exercises Session.Open's closed-session guard.
func TestOpenAfterCloseReturnsError(t *testing.T) {
	client, server := pair(t)
	_ = server
	client.Close()
	if _, err := client.Open([]byte("meta")); err == nil {
		t.Fatal("expected error opening a stream on a closed session")
	}
}

// TestOpenSurfacesWriteFrameError verifies that when the underlying conn write fails, Open both
// returns the error and removes the half-created stream (removeStream branch).
func TestOpenSurfacesWriteFrameError(t *testing.T) {
	c, s := net.Pipe()
	s.Close() // make the other end vanish so client's write eventually errors
	client := Client(c)
	defer client.Close()

	_, err := client.Open([]byte("meta"))
	if err == nil {
		t.Fatal("expected an error opening a stream on a broken pipe")
	}
}

// TestNextControlErrorsAfterClose exercises NextControl's closed-session branch.
func TestNextControlErrorsAfterClose(t *testing.T) {
	client, server := pair(t)
	_ = server
	client.Close()
	if _, err := client.NextControl(); err == nil {
		t.Fatal("expected error from NextControl after Close")
	}
}

// TestClosedChannelClosesOnSessionClose exercises the exported Closed() accessor.
func TestClosedChannelClosesOnSessionClose(t *testing.T) {
	client, server := pair(t)
	_ = server
	select {
	case <-client.Closed():
		t.Fatal("expected Closed() channel to be open before Close")
	default:
	}
	client.Close()
	select {
	case <-client.Closed():
	case <-time.After(time.Second):
		t.Fatal("expected Closed() channel to close after Close")
	}
}

// TestReadLoopDropsUndecodableControlFrame verifies a malformed control payload is skipped (the
// "continue" branch in readLoop's frameControl case) rather than tearing down the session or
// blocking forever.
func TestReadLoopDropsUndecodableControlFrame(t *testing.T) {
	client, server := pair(t)
	defer client.Close()
	defer server.Close()

	// Write a raw, malformed control frame directly onto the wire from the client side; the server's
	// readLoop should silently drop it and continue processing subsequent frames.
	if err := client.writeFrame(frameControl, 0, []byte("not json")); err != nil {
		t.Fatal(err)
	}
	// Now send a valid control message; it should still arrive at the server despite the bad frame.
	if err := client.SendControl(Control{Kind: KindHeartbeat}); err != nil {
		t.Fatal(err)
	}
	got, err := server.NextControl()
	if err != nil {
		t.Fatal(err)
	}
	if got.Kind != KindHeartbeat {
		t.Fatalf("expected heartbeat control after malformed frame, got %+v", got)
	}
}

// TestReadLoopIgnoresDataForUnknownStream verifies a DATA frame for a connID with no local stream
// (e.g. already closed/removed) is dropped rather than panicking.
func TestReadLoopIgnoresDataForUnknownStream(t *testing.T) {
	client, server := pair(t)
	defer client.Close()
	defer server.Close()

	// connID 999 was never opened on either side; server's readLoop must just drop this frame.
	if err := client.writeFrame(frameData, 999, []byte("orphan")); err != nil {
		t.Fatal(err)
	}
	// Follow up with a control message to confirm the session is still healthy afterwards.
	if err := client.SendControl(Control{Kind: KindHeartbeat}); err != nil {
		t.Fatal(err)
	}
	if _, err := server.NextControl(); err != nil {
		t.Fatal(err)
	}
}

// TestReadLoopIgnoresCloseForUnknownStream verifies a CLOSE frame for an unknown connID is a no-op.
func TestReadLoopIgnoresCloseForUnknownStream(t *testing.T) {
	client, server := pair(t)
	defer client.Close()
	defer server.Close()

	if err := client.writeFrame(frameClose, 999, nil); err != nil {
		t.Fatal(err)
	}
	if err := client.SendControl(Control{Kind: KindHeartbeat}); err != nil {
		t.Fatal(err)
	}
	if _, err := server.NextControl(); err != nil {
		t.Fatal(err)
	}
}

// TestWriteDataChunksLargePayload verifies writeData splits a payload larger than MaxPayload into
// multiple frames and the peer reassembles it whole.
func TestWriteDataChunksLargePayload(t *testing.T) {
	client, server := pair(t)

	done := make(chan struct{})
	var got []byte
	go func() {
		defer close(done)
		st, err := server.Accept()
		if err != nil {
			return
		}
		got, _ = io.ReadAll(st)
	}()

	st, err := client.Open(nil)
	if err != nil {
		t.Fatal(err)
	}
	payload := bytes.Repeat([]byte("x"), MaxPayload*2+123)
	if _, err := st.Write(payload); err != nil {
		t.Fatal(err)
	}
	st.Close()

	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for reassembled payload")
	}
	if !bytes.Equal(got, payload) {
		t.Fatalf("chunked payload mismatch: got %d bytes, want %d", len(got), len(payload))
	}
}

// TestStreamWriteAfterCloseFails verifies Write on a locally-closed stream returns net.ErrClosed
// without touching the wire.
func TestStreamWriteAfterCloseFails(t *testing.T) {
	client, server := pair(t)
	defer server.Close()
	go server.Accept()

	st, err := client.Open(nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := st.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := st.Write([]byte("late")); !errors.Is(err, net.ErrClosed) {
		t.Fatalf("expected net.ErrClosed, got %v", err)
	}
}

// TestStreamCloseIsIdempotent verifies calling Close twice is a no-op the second time (doesn't
// double-send a CLOSE frame or error).
func TestStreamCloseIsIdempotent(t *testing.T) {
	client, server := pair(t)
	defer server.Close()
	go server.Accept()

	st, err := client.Open(nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := st.Close(); err != nil {
		t.Fatal(err)
	}
	if err := st.Close(); err != nil {
		t.Fatalf("second Close should be a no-op, got %v", err)
	}
}

// TestStreamReadAfterLocalCloseWithNoDataReturnsErrClosed exercises Read's localClosed branch when
// there's no buffered data and the peer hasn't closed its end.
func TestStreamReadAfterLocalCloseWithNoDataReturnsErrClosed(t *testing.T) {
	client, server := pair(t)
	defer server.Close()

	acceptedCh := make(chan *Stream, 1)
	go func() {
		st, err := server.Accept()
		if err == nil {
			acceptedCh <- st
		}
	}()

	st, err := client.Open(nil)
	if err != nil {
		t.Fatal(err)
	}
	<-acceptedCh // ensure the peer stream exists so it doesn't get GC'd oddly; not otherwise used

	if err := st.Close(); err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, 4)
	_, err = st.Read(buf)
	if !errors.Is(err, net.ErrClosed) {
		t.Fatalf("expected net.ErrClosed, got %v", err)
	}
}

// TestStreamFailUnblocksRead verifies that failing a stream (as closeWithErr does to all live
// streams) causes a blocked Read to return that error. This exercises Stream.fail and Read's
// s.err branch directly, without any session-level teardown that could race with the injected
// error.
func TestStreamFailUnblocksRead(t *testing.T) {
	client, server := pair(t)
	defer client.Close()
	defer server.Close()
	go server.Accept()

	st, err := client.Open(nil)
	if err != nil {
		t.Fatal(err)
	}

	readErr := make(chan error, 1)
	go func() {
		buf := make([]byte, 4)
		_, err := st.Read(buf)
		readErr <- err
	}()

	time.Sleep(10 * time.Millisecond)

	custom := errors.New("injected failure")
	st.fail(custom)

	select {
	case err := <-readErr:
		if !errors.Is(err, custom) {
			t.Fatalf("expected injected failure, got %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("Read did not unblock after fail")
	}
}

// TestStreamAddrAndNetwork covers LocalAddr/RemoteAddr/streamAddr's Network/String methods.
func TestStreamAddrAndNetwork(t *testing.T) {
	client, server := pair(t)
	defer server.Close()
	go server.Accept()

	st, err := client.Open(nil)
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()

	if got := st.LocalAddr().Network(); got != "skybridge-tunnel" {
		t.Fatalf("LocalAddr().Network() = %q", got)
	}
	if got := st.RemoteAddr().Network(); got != "skybridge-tunnel" {
		t.Fatalf("RemoteAddr().Network() = %q", got)
	}
	if got := st.LocalAddr().String(); got != "stream" {
		t.Fatalf("LocalAddr().String() = %q", got)
	}
	if got := st.RemoteAddr().String(); got != "stream" {
		t.Fatalf("RemoteAddr().String() = %q", got)
	}
}

// TestStreamSetDeadlineDelegatesToSetReadDeadline covers the SetDeadline wrapper.
func TestStreamSetDeadlineDelegatesToSetReadDeadline(t *testing.T) {
	client, server := pair(t)
	defer server.Close()
	go server.Accept()

	st, err := client.Open(nil)
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()

	if err := st.SetDeadline(time.Now().Add(20 * time.Millisecond)); err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, 4)
	if _, err := st.Read(buf); err == nil {
		t.Fatal("expected deadline error via SetDeadline")
	}
}

// TestStreamSetReadDeadlineZeroClearsExpiry verifies passing a zero time cancels a previously armed
// timer instead of leaving Read spuriously erroring.
func TestStreamSetReadDeadlineZeroClearsExpiry(t *testing.T) {
	client, server := pair(t)

	go func() {
		st, err := server.Accept()
		if err != nil {
			return
		}
		time.Sleep(30 * time.Millisecond)
		st.Write([]byte("hi"))
	}()

	st, err := client.Open(nil)
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()

	st.SetReadDeadline(time.Now().Add(5 * time.Millisecond))
	st.SetReadDeadline(time.Time{}) // clear before it fires

	buf := make([]byte, 2)
	n, err := st.Read(buf)
	if err != nil {
		t.Fatalf("expected read to succeed after clearing deadline, got err=%v", err)
	}
	if string(buf[:n]) != "hi" {
		t.Fatalf("got %q", buf[:n])
	}
}

// TestStreamSetWriteDeadlineIsNoop covers SetWriteDeadline's documented no-op behavior.
func TestStreamSetWriteDeadlineIsNoop(t *testing.T) {
	client, server := pair(t)
	defer server.Close()
	go server.Accept()

	st, err := client.Open(nil)
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()

	if err := st.SetWriteDeadline(time.Now().Add(time.Second)); err != nil {
		t.Fatalf("expected SetWriteDeadline to always succeed, got %v", err)
	}
}

// TestStreamDeliverFailsOnBufferOverflow is the regression test for maxStreamBufferBytes: before it
// existed, Stream.deliver appended every inbound data frame to its buffer with no cap — a peer that
// keeps sending data for a stream nobody is draining (or a stalled consumer) could grow that one
// stream's buffer without limit. It must now fail the stream instead.
func TestStreamDeliverFailsOnBufferOverflow(t *testing.T) {
	st := newStream(nil, 1, nil)
	half := make([]byte, maxStreamBufferBytes/2+1)
	st.deliver(half)
	st.deliver(half) // cumulative > maxStreamBufferBytes

	st.mu.Lock()
	err := st.err
	st.mu.Unlock()
	if !errors.Is(err, errStreamBufferOverflow) {
		t.Fatalf("expected errStreamBufferOverflow, got %v", err)
	}

	// Read must still drain whatever was already buffered before the overflowing delivery (the
	// first half succeeded) — fallthrough-never-corrupt applies here too, the error surfaces once
	// the buffer is drained, not by discarding already-buffered bytes.
	drained := make([]byte, 0, len(half))
	buf := make([]byte, 4096)
	for len(drained) < len(half) {
		n, rerr := st.Read(buf)
		drained = append(drained, buf[:n]...)
		if rerr != nil {
			t.Fatalf("unexpected error while draining already-buffered bytes: %v", rerr)
		}
	}

	// Only once the buffer is empty does Read surface the failure rather than hang.
	if _, err := st.Read(buf); !errors.Is(err, errStreamBufferOverflow) {
		t.Fatalf("expected Read to surface errStreamBufferOverflow after draining, got %v", err)
	}
}

// TestStreamDeliverWithinLimitStillWorks confirms the cap doesn't reject ordinary, merely large
// (not adversarial) bursts of buffered data.
func TestStreamDeliverWithinLimitStillWorks(t *testing.T) {
	st := newStream(nil, 1, nil)
	chunk := make([]byte, maxStreamBufferBytes-1)
	st.deliver(chunk)

	st.mu.Lock()
	err := st.err
	buffered := st.buf.Len()
	st.mu.Unlock()
	if err != nil {
		t.Fatalf("expected no error within the limit, got %v", err)
	}
	if buffered != len(chunk) {
		t.Fatalf("expected %d buffered bytes, got %d", len(chunk), buffered)
	}
}

// TestReadLoopDropsOpenFramesBeyondMaxStreams is the regression test for maxStreams: before it
// existed, a peer sending unlimited "open" frames grew Session.streams without limit. maxStreams is
// temporarily lowered rather than actually opening thousands of streams.
func TestReadLoopDropsOpenFramesBeyondMaxStreams(t *testing.T) {
	orig := maxStreams
	maxStreams = 1
	defer func() { maxStreams = orig }()

	client, server := pair(t)
	defer client.Close()
	defer server.Close()

	if _, err := client.Open([]byte("first")); err != nil {
		t.Fatal(err)
	}
	// Open() returns successfully on the sending side regardless of what the peer does with the
	// frame (it doesn't wait for an ack) — the second stream's "open" frame should be silently
	// dropped by the server once it's already at the (lowered) limit of 1.
	if _, err := client.Open([]byte("second")); err != nil {
		t.Fatal(err)
	}

	st1, err := server.Accept()
	if err != nil {
		t.Fatal(err)
	}
	if string(st1.Meta()) != "first" {
		t.Fatalf("expected the first stream accepted, got meta %q", st1.Meta())
	}

	select {
	case st2 := <-server.accept:
		t.Fatalf("expected the second stream to be dropped past maxStreams, got accepted meta %q", st2.Meta())
	case <-time.After(100 * time.Millisecond):
		// expected: nothing else ever gets accepted
	}
}

// TestRunReadLoopRecoversPanic is the regression test for the core tunnel-hardening fix: a panic
// anywhere inside readLoop (a malformed/adversarial frame hitting an unhandled parsing edge case)
// must close this one session with a recorded error, not crash the whole agent/gateway process and
// take down every other tenant's session sharing it. Before runReadLoop existed, this would have
// crashed the test binary itself.
func TestRunReadLoopRecoversPanic(t *testing.T) {
	// conn is intentionally left nil: readFrame calling a method on a nil net.Conn interface value
	// panics with a nil-pointer runtime error, standing in for any other parsing bug that might
	// panic deep inside readLoop.
	s := &Session{
		streams:   make(map[uint64]*Stream),
		accept:    make(chan *Stream, 1),
		controlCh: make(chan Control, 1),
		closed:    make(chan struct{}),
	}
	s.runReadLoop()

	select {
	case <-s.closed:
	default:
		t.Fatal("expected the session to be closed after recovering from the panic")
	}
	if s.err == nil {
		t.Fatal("expected a recorded error after recovering from the panic")
	}
}
