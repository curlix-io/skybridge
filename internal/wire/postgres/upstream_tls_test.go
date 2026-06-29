package postgres

import (
	"crypto/tls"
	"encoding/binary"
	"io"
	"net"
	"testing"
)

// readSSLRequest reads the 8-byte SSLRequest the agent sends to the upstream and asserts it is the
// expected sentinel.
func readSSLRequest(t *testing.T, r io.Reader) {
	t.Helper()
	var b [8]byte
	if _, err := io.ReadFull(r, b[:]); err != nil {
		t.Fatalf("read SSLRequest: %v", err)
	}
	if binary.BigEndian.Uint32(b[0:4]) != 8 || binary.BigEndian.Uint32(b[4:8]) != sslRequestCode {
		t.Fatalf("not an SSLRequest: len=%d code=%d", binary.BigEndian.Uint32(b[0:4]), binary.BigEndian.Uint32(b[4:8]))
	}
}

// TestStartUpstreamTLSUpgrades is the core of upstream TLS: the agent sends SSLRequest, the upstream
// answers 'S', and the agent completes a TLS handshake so the startup/auth bytes that follow are
// encrypted.
func TestStartUpstreamTLSUpgrades(t *testing.T) {
	agentEnd, upstreamEnd := net.Pipe()
	defer agentEnd.Close()
	defer upstreamEnd.Close()
	deadline(t, agentEnd, upstreamEnd)

	type result struct {
		conn net.Conn
		err  error
	}
	out := make(chan result, 1)
	go func() {
		conn, err := StartUpstreamTLS(agentEnd, &tls.Config{InsecureSkipVerify: true}, true) //nolint:gosec // test
		out <- result{conn: conn, err: err}
	}()

	// Upstream side: read SSLRequest, accept ('S'), then TLS-server handshake + read a probe byte.
	readSSLRequest(t, upstreamEnd)
	if _, err := upstreamEnd.Write([]byte{'S'}); err != nil {
		t.Fatalf("write 'S': %v", err)
	}
	srv := tls.Server(upstreamEnd, testTLSConfig(t))
	srvErr := make(chan error, 1)
	go func() {
		if err := srv.Handshake(); err != nil {
			srvErr <- err
			return
		}
		buf := make([]byte, 5)
		_, err := io.ReadFull(srv, buf)
		if err == nil && string(buf) != "hello" {
			err = io.ErrUnexpectedEOF
		}
		srvErr <- err
	}()

	r := <-out
	if r.err != nil {
		t.Fatalf("StartUpstreamTLS: %v", r.err)
	}
	if _, ok := r.conn.(*tls.Conn); !ok {
		t.Fatalf("expected a *tls.Conn, got %T", r.conn)
	}
	if _, err := r.conn.Write([]byte("hello")); err != nil {
		t.Fatalf("write over upstream TLS: %v", err)
	}
	if err := <-srvErr; err != nil {
		t.Fatalf("upstream TLS server: %v", err)
	}
}

// TestStartUpstreamTLSRequiredButDeclined: a server that does not offer SSL ('N') is a hard failure
// when TLS is required (require/verify-*), so the agent never falls back to plaintext.
func TestStartUpstreamTLSRequiredButDeclined(t *testing.T) {
	agentEnd, upstreamEnd := net.Pipe()
	defer agentEnd.Close()
	defer upstreamEnd.Close()
	deadline(t, agentEnd, upstreamEnd)

	errc := make(chan error, 1)
	go func() {
		_, err := StartUpstreamTLS(agentEnd, &tls.Config{InsecureSkipVerify: true}, true) //nolint:gosec // test
		errc <- err
	}()
	readSSLRequest(t, upstreamEnd)
	if _, err := upstreamEnd.Write([]byte{'N'}); err != nil {
		t.Fatalf("write 'N': %v", err)
	}
	if err := <-errc; err == nil {
		t.Fatal("expected an error when TLS is required but the upstream declined SSL")
	}
}

// TestStartUpstreamTLSPreferFallsBack: with prefer (required=false) a declining server yields the
// original plaintext connection so the session can still proceed.
func TestStartUpstreamTLSPreferFallsBack(t *testing.T) {
	agentEnd, upstreamEnd := net.Pipe()
	defer agentEnd.Close()
	defer upstreamEnd.Close()
	deadline(t, agentEnd, upstreamEnd)

	type result struct {
		conn net.Conn
		err  error
	}
	out := make(chan result, 1)
	go func() {
		conn, err := StartUpstreamTLS(agentEnd, &tls.Config{InsecureSkipVerify: true}, false) //nolint:gosec // test
		out <- result{conn: conn, err: err}
	}()
	readSSLRequest(t, upstreamEnd)
	if _, err := upstreamEnd.Write([]byte{'N'}); err != nil {
		t.Fatalf("write 'N': %v", err)
	}
	r := <-out
	if r.err != nil {
		t.Fatalf("prefer fallback should not error: %v", r.err)
	}
	if _, ok := r.conn.(*tls.Conn); ok {
		t.Fatal("prefer fallback should return the plaintext conn, not a *tls.Conn")
	}
	if r.conn != agentEnd {
		t.Fatal("prefer fallback should return the original connection unchanged")
	}
}
