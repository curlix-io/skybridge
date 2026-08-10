package wire

import (
	"io"
	"net"
	"testing"
	"time"
)

func TestNoopRecorderDiscardsInputAndOutput(t *testing.T) {
	// NoopRecorder's methods must be safe to call and must not panic or otherwise observably do
	// anything — it's the default when session replay is disabled.
	var rec NoopRecorder
	rec.RecordInput([]byte("client bytes"))
	rec.RecordOutput("rendered row")
}

func TestRecorderInputWriterTeesIntoRecorder(t *testing.T) {
	got := &capturingRecorder{}
	w := RecorderInputWriter(got)

	n, err := w.Write([]byte("hello"))
	if err != nil {
		t.Fatalf("Write returned error: %v", err)
	}
	if n != 5 {
		t.Fatalf("Write returned n=%d, want 5", n)
	}
	if len(got.inputs) != 1 || string(got.inputs[0]) != "hello" {
		t.Fatalf("expected recorder to observe %q, got %v", "hello", got.inputs)
	}
}

type capturingRecorder struct {
	inputs  [][]byte
	outputs []string
}

func (c *capturingRecorder) RecordInput(raw []byte) {
	c.inputs = append(c.inputs, append([]byte(nil), raw...))
}

func (c *capturingRecorder) RecordOutput(text string) {
	c.outputs = append(c.outputs, text)
}

func TestPassthroughCopiesBothDirectionsUntilClientCloses(t *testing.T) {
	clientA, clientB := net.Pipe()
	upstreamA, upstreamB := net.Pipe()

	done := make(chan error, 1)
	go func() { done <- Passthrough(clientB, upstreamB) }()

	if _, err := clientA.Write([]byte("hello upstream")); err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, 32)
	n, err := upstreamA.Read(buf)
	if err != nil {
		t.Fatal(err)
	}
	if string(buf[:n]) != "hello upstream" {
		t.Fatalf("got %q, want %q", buf[:n], "hello upstream")
	}

	if _, err := upstreamA.Write([]byte("hello client")); err != nil {
		t.Fatal(err)
	}
	n, err = clientA.Read(buf)
	if err != nil {
		t.Fatal(err)
	}
	if string(buf[:n]) != "hello client" {
		t.Fatalf("got %q, want %q", buf[:n], "hello client")
	}

	if err := clientA.Close(); err != nil {
		t.Fatal(err)
	}

	select {
	case err := <-done:
		if err != nil && err != io.EOF && err != io.ErrClosedPipe {
			t.Fatalf("unexpected Passthrough error: %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("Passthrough did not return after client closed")
	}
}

func TestPassthroughClosesBothConnsOnReturn(t *testing.T) {
	clientA, clientB := net.Pipe()
	upstreamA, upstreamB := net.Pipe()

	done := make(chan error, 1)
	go func() { done <- Passthrough(clientB, upstreamB) }()

	_ = clientA.Close()
	_ = upstreamA.Close()

	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("Passthrough did not return")
	}

	if _, err := clientB.Write([]byte("x")); err == nil {
		t.Fatal("expected client-side conn to be closed by Passthrough")
	}
	if _, err := upstreamB.Write([]byte("x")); err == nil {
		t.Fatal("expected upstream-side conn to be closed by Passthrough")
	}
}
