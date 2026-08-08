package wire

import (
	"io"
	"net"
	"testing"
	"time"
)

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
