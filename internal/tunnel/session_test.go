package tunnel

import (
	"bytes"
	"fmt"
	"io"
	"net"
	"sync"
	"testing"
	"time"
)

func TestFrameRoundTrip(t *testing.T) {
	var buf bytes.Buffer
	payload := []byte("hello frame")
	if err := writeFrameTo(&buf, frameData, 42, payload); err != nil {
		t.Fatal(err)
	}
	f, err := readFrame(&buf)
	if err != nil {
		t.Fatal(err)
	}
	if f.typ != frameData || f.connID != 42 || !bytes.Equal(f.payload, payload) {
		t.Fatalf("round-trip mismatch: %+v", f)
	}
}

func TestFrameRejectsBadMagic(t *testing.T) {
	if _, err := readFrame(bytes.NewReader(make([]byte, headerLen))); err == nil {
		t.Fatal("expected bad-magic error")
	}
}

// pair returns a connected client/server Session backed by net.Pipe.
func pair(t *testing.T) (*Session, *Session) {
	t.Helper()
	c, s := net.Pipe()
	cs := Client(c)
	ss := Server(s)
	t.Cleanup(func() { cs.Close(); ss.Close() })
	return cs, ss
}

func TestStreamOpenDataClose(t *testing.T) {
	client, server := pair(t)

	go func() {
		st, err := server.Accept()
		if err != nil {
			return
		}
		if got := string(st.Meta()); got != "meta-1" {
			t.Errorf("meta = %q", got)
		}
		io.Copy(st, st) // echo
	}()

	st, err := client.Open([]byte("meta-1"))
	if err != nil {
		t.Fatal(err)
	}
	msg := []byte("ping over the tunnel")
	if _, err := st.Write(msg); err != nil {
		t.Fatal(err)
	}
	got := make([]byte, len(msg))
	if _, err := io.ReadFull(st, got); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, msg) {
		t.Fatalf("echo mismatch: %q", got)
	}

	// Closing the local stream should surface EOF to the peer's Read.
	if err := st.Close(); err != nil {
		t.Fatal(err)
	}
}

func TestStreamRemoteCloseEOF(t *testing.T) {
	client, server := pair(t)
	go func() {
		st, err := server.Accept()
		if err != nil {
			return
		}
		st.Write([]byte("bye"))
		st.Close()
	}()

	st, err := client.Open(nil)
	if err != nil {
		t.Fatal(err)
	}
	data, err := io.ReadAll(st)
	if err != nil {
		t.Fatalf("ReadAll: %v", err)
	}
	if string(data) != "bye" {
		t.Fatalf("got %q", data)
	}
}

func TestConcurrentStreams(t *testing.T) {
	client, server := pair(t)

	go func() {
		for {
			st, err := server.Accept()
			if err != nil {
				return
			}
			go io.Copy(st, st)
		}
	}()

	const n = 20
	var wg sync.WaitGroup
	wg.Add(n)
	errs := make(chan error, n)
	for i := 0; i < n; i++ {
		go func(i int) {
			defer wg.Done()
			st, err := client.Open([]byte(fmt.Sprintf("s%d", i)))
			if err != nil {
				errs <- err
				return
			}
			defer st.Close()
			want := []byte(fmt.Sprintf("payload-%d-%d", i, i*7))
			if _, err := st.Write(want); err != nil {
				errs <- err
				return
			}
			got := make([]byte, len(want))
			if _, err := io.ReadFull(st, got); err != nil {
				errs <- err
				return
			}
			if !bytes.Equal(got, want) {
				errs <- fmt.Errorf("stream %d: got %q want %q", i, got, want)
			}
		}(i)
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		t.Fatal(err)
	}
}

func TestControlChannel(t *testing.T) {
	client, server := pair(t)

	if err := client.SendControl(Control{Kind: KindRegister, AgentID: "a1", Token: "tok"}); err != nil {
		t.Fatal(err)
	}
	got, err := server.NextControl()
	if err != nil {
		t.Fatal(err)
	}
	if got.Kind != KindRegister || got.AgentID != "a1" || got.Token != "tok" {
		t.Fatalf("control mismatch: %+v", got)
	}
}

func TestSessionCloseUnblocksAccept(t *testing.T) {
	_, server := pair(t)
	done := make(chan struct{})
	go func() {
		_, err := server.Accept()
		if err == nil {
			t.Error("expected error after close")
		}
		close(done)
	}()
	time.Sleep(10 * time.Millisecond)
	server.Close()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("Accept did not unblock on close")
	}
}

func TestReadDeadline(t *testing.T) {
	client, server := pair(t)
	go server.Accept()
	st, err := client.Open(nil)
	if err != nil {
		t.Fatal(err)
	}
	st.SetReadDeadline(time.Now().Add(20 * time.Millisecond))
	buf := make([]byte, 4)
	_, err = st.Read(buf)
	if err == nil {
		t.Fatal("expected deadline error")
	}
}
