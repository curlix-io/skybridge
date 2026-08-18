package k8sapi

import (
	"bufio"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"io"
	"math/big"
	"net"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/curlix-io/skybridge/internal/wire"
)

// selfSignedTLSConfig builds a server tls.Config with a fresh self-signed cert (mirrors
// postgres/tls_test.go's testTLSConfig).
func selfSignedTLSConfig(t *testing.T) *tls.Config {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("key: %v", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "skybridge-test"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		DNSNames:     []string{"localhost"},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("cert: %v", err)
	}
	keyDER, _ := x509.MarshalECPrivateKey(key)
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})
	cert, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		t.Fatalf("keypair: %v", err)
	}
	return &tls.Config{Certificates: []tls.Certificate{cert}, MinVersion: tls.VersionTLS12}
}

// fakeUpstream is a net.Pipe-backed stand-in for the "real cluster API server": it reads one HTTP
// request off its end and writes back a canned response, capturing the Authorization header it
// received so the test can assert the session token was swapped for the real bearer token.
type fakeUpstream struct {
	gotAuth  string
	respBody string
	status   int
}

func serveFakeUpstream(t *testing.T, conn net.Conn, tlsCfg *tls.Config, fu *fakeUpstream) {
	t.Helper()
	tconn := tls.Server(conn, tlsCfg)
	if err := tconn.Handshake(); err != nil {
		t.Errorf("upstream TLS handshake: %v", err)
		return
	}
	defer tconn.Close()
	r := bufio.NewReader(tconn)
	req, err := http.ReadRequest(r)
	if err != nil {
		if !errors.Is(err, io.EOF) {
			t.Errorf("upstream read request: %v", err)
		}
		return
	}
	fu.gotAuth = req.Header.Get("Authorization")
	_, _ = io.Copy(io.Discard, req.Body)

	status := fu.status
	if status == 0 {
		status = http.StatusOK
	}
	resp := "HTTP/1.1 " + http.StatusText(status) + "\r\n"
	resp = "HTTP/1.1 200 OK\r\n"
	if status != http.StatusOK {
		resp = "HTTP/1.1 " + itoa(status) + " " + http.StatusText(status) + "\r\n"
	}
	body := fu.respBody
	resp += "Content-Type: application/json\r\n"
	resp += "Content-Length: " + itoa(len(body)) + "\r\n\r\n" + body
	_, _ = tconn.Write([]byte(resp))
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	digits := []byte{}
	for n > 0 {
		digits = append([]byte{byte('0' + n%10)}, digits...)
		n /= 10
	}
	return string(digits)
}

func TestProxyInjectSwapsTokenAndMasksResponse(t *testing.T) {
	clientPlain, agentClientEnd := net.Pipe()
	agentUpstreamEnd, upstreamPlain := net.Pipe()
	defer clientPlain.Close()

	serverTLS := selfSignedTLSConfig(t)
	fu := &fakeUpstream{respBody: `{"kind":"Secret","data":{"password":"cGFzcw=="}}`}
	go serveFakeUpstream(t, upstreamPlain, serverTLS, fu)

	resolver := func(ctx context.Context, sessionToken string) (UpstreamCredential, error) {
		if sessionToken != "session-token" {
			return UpstreamCredential{}, errors.New("bad token")
		}
		return UpstreamCredential{BearerToken: "real-cluster-token", InsecureSkipVerify: true}, nil
	}

	engine := New(serverTLS)
	done := make(chan error, 1)
	go func() {
		done <- engine.ProxyInject(context.Background(), agentClientEnd, agentUpstreamEnd, resolver, wire.NoopRecorder{})
	}()

	clientTLSConn := tls.Client(clientPlain, &tls.Config{InsecureSkipVerify: true}) //nolint:gosec // test
	req, err := http.NewRequest(http.MethodGet, "https://cluster/api/v1/namespaces/default/secrets/my-secret", nil)
	if err != nil {
		t.Fatalf("new request: %v", err)
	}
	req.Header.Set("Authorization", "Bearer session-token")
	if err := req.Write(clientTLSConn); err != nil {
		t.Fatalf("write request: %v", err)
	}

	resp, err := http.ReadResponse(bufio.NewReader(clientTLSConn), req)
	if err != nil {
		t.Fatalf("read response: %v", err)
	}
	body, _ := io.ReadAll(resp.Body)
	_ = clientTLSConn.Close()

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", resp.StatusCode, body)
	}
	if fu.gotAuth != "Bearer real-cluster-token" {
		t.Fatalf("expected upstream to see real cluster token, got %q", fu.gotAuth)
	}
	if !strings.Contains(string(body), redacted) {
		t.Fatalf("expected masked secret data, got %s", body)
	}

	_ = agentClientEnd.Close()
	select {
	case err := <-done:
		if err != nil && !errors.Is(err, io.EOF) && !errors.Is(err, net.ErrClosed) {
			t.Fatalf("ProxyInject returned unexpected error: %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("ProxyInject did not return after client close")
	}
}

func TestProxyInjectRejectsMissingBearerToken(t *testing.T) {
	clientPlain, agentClientEnd := net.Pipe()
	_, agentUpstreamEnd := net.Pipe()
	defer clientPlain.Close()

	serverTLS := selfSignedTLSConfig(t)
	resolver := func(ctx context.Context, sessionToken string) (UpstreamCredential, error) {
		t.Fatal("resolver should not be called without a bearer token")
		return UpstreamCredential{}, nil
	}

	engine := New(serverTLS)
	done := make(chan error, 1)
	go func() {
		done <- engine.ProxyInject(context.Background(), agentClientEnd, agentUpstreamEnd, resolver, wire.NoopRecorder{})
	}()

	clientTLSConn := tls.Client(clientPlain, &tls.Config{InsecureSkipVerify: true}) //nolint:gosec // test
	req, _ := http.NewRequest(http.MethodGet, "https://cluster/api/v1/namespaces/default/pods", nil)
	if err := req.Write(clientTLSConn); err != nil {
		t.Fatalf("write request: %v", err)
	}
	resp, err := http.ReadResponse(bufio.NewReader(clientTLSConn), req)
	if err != nil {
		t.Fatalf("read response: %v", err)
	}
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("expected 401, got %d", resp.StatusCode)
	}
	_ = clientTLSConn.Close()
	<-done
}

func TestNegotiateUpstreamTLSHandshakeFailure(t *testing.T) {
	upstreamA, upstreamB := net.Pipe()
	defer upstreamB.Close()
	go func() {
		buf := make([]byte, 4096)
		_, _ = upstreamB.Read(buf)
		_ = upstreamB.Close()
	}()

	_, err := negotiateUpstreamTLS(upstreamA, UpstreamCredential{InsecureSkipVerify: true})
	if err == nil || !strings.Contains(err.Error(), "upstream TLS handshake") {
		t.Fatalf("expected upstream TLS handshake error, got %v", err)
	}
}

func TestNegotiateUpstreamTLSWithValidCACertPEM(t *testing.T) {
	// negotiateUpstreamTLS derives ServerName from upstream.RemoteAddr() when a CACertPEM is
	// supplied without InsecureSkipVerify, so cluster-CA-pinned upstream verification succeeds
	// against a well-behaved upstream reachable over a real (non-net.Pipe) connection — net.Pipe's
	// RemoteAddr() is the string "pipe", which has no host to derive a ServerName from, so this test
	// uses a real TCP loopback listener instead.
	certPEM, tlsCert := selfSignedCertPEM(t)
	serverCfg := &tls.Config{Certificates: []tls.Certificate{tlsCert}}

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer ln.Close()
	go func() {
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		tconn := tls.Server(conn, serverCfg)
		_ = tconn.Handshake()
		_ = tconn.Close()
	}()

	upstream, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer upstream.Close()

	tconn, err := negotiateUpstreamTLS(upstream, UpstreamCredential{CACertPEM: certPEM, InsecureSkipVerify: false})
	if err != nil {
		t.Fatalf("expected handshake to succeed with ServerName derived from the upstream's remote address, got: %v", err)
	}
	defer tconn.Close()
}

func TestRecordRequestBodyNilBody(t *testing.T) {
	rec := &captureRecorder{}
	req, _ := http.NewRequest(http.MethodGet, "http://cluster/api/v1/namespaces/default/pods", nil)
	req.Body = nil
	if err := recordRequestBody(rec, req); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(rec.inputs) != 1 || rec.inputs[0] != "GET /api/v1/namespaces/default/pods" {
		t.Fatalf("unexpected recorded input: %v", rec.inputs)
	}
}

func TestRecordRequestBodyWithBody(t *testing.T) {
	rec := &captureRecorder{}
	req, _ := http.NewRequest(http.MethodPost, "http://cluster/api/v1/namespaces/default/pods", strings.NewReader(`{"a":1}`))
	if err := recordRequestBody(rec, req); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(rec.inputs) != 1 || !strings.Contains(rec.inputs[0], `{"a":1}`) {
		t.Fatalf("expected body captured in recorded input, got %v", rec.inputs)
	}
	// The body must still be readable downstream after recordRequestBody re-wraps it.
	replayed, err := io.ReadAll(req.Body)
	if err != nil {
		t.Fatalf("re-reading req.Body: %v", err)
	}
	if string(replayed) != `{"a":1}` {
		t.Fatalf("expected req.Body replayable, got %q", replayed)
	}
}

// TestRecordRequestBodyRejectsOversizedBody is the regression test for maxBodyBytes: before it
// existed, recordRequestBody's io.ReadAll(req.Body) had no size ceiling at all — a malicious
// client could stream an effectively unbounded request body and exhaust agent memory. It must now
// error instead of buffering an unbounded amount.
func TestRecordRequestBodyRejectsOversizedBody(t *testing.T) {
	rec := &captureRecorder{}
	// io.MultiReader avoids actually allocating maxBodyBytes+2 bytes up front — the reader lazily
	// produces bytes, and recordRequestBody's own LimitReader(maxBodyBytes+1) is what should trip.
	oversized := io.MultiReader(&repeatReader{n: maxBodyBytes + 2})
	req, _ := http.NewRequest(http.MethodPost, "http://cluster/api/v1/namespaces/default/pods", oversized)
	if err := recordRequestBody(rec, req); err == nil {
		t.Fatal("expected an error for a body exceeding maxBodyBytes")
	}
}

// repeatReader yields n arbitrary bytes without materializing them all in memory at once.
type repeatReader struct{ n int }

func (r *repeatReader) Read(p []byte) (int, error) {
	if r.n <= 0 {
		return 0, io.EOF
	}
	if len(p) > r.n {
		p = p[:r.n]
	}
	for i := range p {
		p[i] = 'x'
	}
	r.n -= len(p)
	return len(p), nil
}

type captureRecorder struct {
	inputs  []string
	outputs []string
}

func (c *captureRecorder) RecordInput(raw []byte)   { c.inputs = append(c.inputs, string(raw)) }
func (c *captureRecorder) RecordOutput(text string) { c.outputs = append(c.outputs, text) }

func TestDrainAndCloseNilBody(t *testing.T) {
	// Must not panic on a nil body (e.g. a GET request with no body).
	drainAndClose(nil)
}

func TestDrainAndCloseDrainsAndCloses(t *testing.T) {
	rc := io.NopCloser(strings.NewReader("leftover unread bytes"))
	drainAndClose(rc)
	// NopCloser's Close is a no-op, so just confirm draining doesn't error/panic and consumes input.
	n, err := rc.Read(make([]byte, 1))
	if err != io.EOF && n != 0 {
		t.Fatalf("expected reader drained to EOF, got n=%d err=%v", n, err)
	}
}

// selfSignedCertPEM builds a fresh self-signed cert and returns both its PEM-encoded bytes and the
// parsed tls.Certificate, for tests that need the raw PEM to feed into UpstreamCredential.CACertPEM.
func selfSignedCertPEM(t *testing.T) ([]byte, tls.Certificate) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("key: %v", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "skybridge-test"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		DNSNames:     []string{"localhost"},
		IPAddresses:  []net.IP{net.ParseIP("127.0.0.1")},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("cert: %v", err)
	}
	keyDER, _ := x509.MarshalECPrivateKey(key)
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})
	cert, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		t.Fatalf("keypair: %v", err)
	}
	return certPEM, cert
}

func TestEngineName(t *testing.T) {
	e := New(nil)
	if e.Name() != "kubernetes" {
		t.Fatalf("expected Name()=kubernetes, got %q", e.Name())
	}
}

func TestProxyInjectRequiresResolver(t *testing.T) {
	clientA, clientB := net.Pipe()
	defer clientA.Close()
	defer clientB.Close()
	upstreamA, upstreamB := net.Pipe()
	defer upstreamA.Close()
	defer upstreamB.Close()

	engine := New(selfSignedTLSConfig(t))
	err := engine.ProxyInject(context.Background(), clientB, upstreamB, nil, wire.NoopRecorder{})
	if err == nil || !strings.Contains(err.Error(), "credential injection requires a resolver") {
		t.Fatalf("expected resolver-required error, got %v", err)
	}
}

func TestProxyInjectRequiresClientTLS(t *testing.T) {
	clientA, clientB := net.Pipe()
	defer clientA.Close()
	defer clientB.Close()
	upstreamA, upstreamB := net.Pipe()
	defer upstreamA.Close()
	defer upstreamB.Close()

	resolver := func(ctx context.Context, sessionToken string) (UpstreamCredential, error) {
		t.Fatal("resolver should not be called when client TLS is unconfigured")
		return UpstreamCredential{}, nil
	}
	engine := New(nil)
	err := engine.ProxyInject(context.Background(), clientB, upstreamB, resolver, nil)
	if err == nil || !strings.Contains(err.Error(), "client TLS must be configured") {
		t.Fatalf("expected client-TLS-required error, got %v", err)
	}
}

func TestProxyInjectFailsOnBadClientHandshake(t *testing.T) {
	clientA, clientB := net.Pipe()
	upstreamA, upstreamB := net.Pipe()
	defer upstreamA.Close()
	defer upstreamB.Close()

	resolver := func(ctx context.Context, sessionToken string) (UpstreamCredential, error) {
		t.Fatal("resolver should not be called when the client TLS handshake fails")
		return UpstreamCredential{}, nil
	}
	engine := New(selfSignedTLSConfig(t))
	done := make(chan error, 1)
	go func() {
		done <- engine.ProxyInject(context.Background(), clientB, upstreamB, resolver, wire.NoopRecorder{})
	}()

	// Write non-TLS bytes at the "server" so its TLS handshake fails.
	_, _ = clientA.Write([]byte("not a tls handshake at all, definitely not"))
	_ = clientA.Close()

	select {
	case err := <-done:
		if err == nil || !strings.Contains(err.Error(), "client TLS handshake") {
			t.Fatalf("expected client TLS handshake error, got %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("ProxyInject did not return after bad client handshake")
	}
}

func TestProxyInjectRejectsResolverError(t *testing.T) {
	clientPlain, agentClientEnd := net.Pipe()
	_, agentUpstreamEnd := net.Pipe()
	defer clientPlain.Close()

	serverTLS := selfSignedTLSConfig(t)
	resolver := func(ctx context.Context, sessionToken string) (UpstreamCredential, error) {
		return UpstreamCredential{}, errors.New("session expired")
	}

	engine := New(serverTLS)
	done := make(chan error, 1)
	go func() {
		done <- engine.ProxyInject(context.Background(), agentClientEnd, agentUpstreamEnd, resolver, wire.NoopRecorder{})
	}()

	clientTLSConn := tls.Client(clientPlain, &tls.Config{InsecureSkipVerify: true}) //nolint:gosec // test
	req, _ := http.NewRequest(http.MethodGet, "https://cluster/api/v1/namespaces/default/pods", nil)
	req.Header.Set("Authorization", "Bearer session-token")
	if err := req.Write(clientTLSConn); err != nil {
		t.Fatalf("write request: %v", err)
	}
	resp, err := http.ReadResponse(bufio.NewReader(clientTLSConn), req)
	if err != nil {
		t.Fatalf("read response: %v", err)
	}
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("expected 403, got %d", resp.StatusCode)
	}
	_ = clientTLSConn.Close()
	<-done
}

func TestProxyInjectBadGatewayOnUpstreamTLSFailure(t *testing.T) {
	clientPlain, agentClientEnd := net.Pipe()
	agentUpstreamEnd, upstreamPlain := net.Pipe()
	defer clientPlain.Close()

	// upstreamPlain never speaks TLS back — negotiateUpstreamTLS's handshake must fail.
	go func() {
		buf := make([]byte, 4096)
		_, _ = upstreamPlain.Read(buf)
		_ = upstreamPlain.Close()
	}()

	serverTLS := selfSignedTLSConfig(t)
	resolver := func(ctx context.Context, sessionToken string) (UpstreamCredential, error) {
		return UpstreamCredential{BearerToken: "real-token", InsecureSkipVerify: true}, nil
	}

	engine := New(serverTLS)
	done := make(chan error, 1)
	go func() {
		done <- engine.ProxyInject(context.Background(), agentClientEnd, agentUpstreamEnd, resolver, wire.NoopRecorder{})
	}()

	clientTLSConn := tls.Client(clientPlain, &tls.Config{InsecureSkipVerify: true}) //nolint:gosec // test
	req, _ := http.NewRequest(http.MethodGet, "https://cluster/api/v1/namespaces/default/pods", nil)
	req.Header.Set("Authorization", "Bearer session-token")
	if err := req.Write(clientTLSConn); err != nil {
		t.Fatalf("write request: %v", err)
	}
	resp, err := http.ReadResponse(bufio.NewReader(clientTLSConn), req)
	if err != nil {
		t.Fatalf("read response: %v", err)
	}
	if resp.StatusCode != http.StatusBadGateway {
		t.Fatalf("expected 502, got %d", resp.StatusCode)
	}
	_ = clientTLSConn.Close()

	select {
	case err := <-done:
		if err == nil {
			t.Fatal("expected ProxyInject to return the upstream TLS handshake error")
		}
	case <-time.After(2 * time.Second):
		t.Fatal("ProxyInject did not return after upstream TLS failure")
	}
}

// TestProxyInjectRejectsInteractiveSubresource covers the default posture: a session whose
// resolved credential does not explicitly set AllowInteractiveExec is rejected exactly as before
// this field existed. Unlike the pre-§11.6 behavior, the resolver IS now called (the decision to
// allow or block exec lives in the resolved credential, not in a path-only check) — see
// TestProxyInjectAllowsInteractiveExecWhenGranted for the opt-in case.
func TestProxyInjectRejectsInteractiveSubresource(t *testing.T) {
	clientPlain, agentClientEnd := net.Pipe()
	_, agentUpstreamEnd := net.Pipe()
	defer clientPlain.Close()

	serverTLS := selfSignedTLSConfig(t)
	resolver := func(ctx context.Context, sessionToken string) (UpstreamCredential, error) {
		return UpstreamCredential{BearerToken: "real-cluster-token"}, nil // AllowInteractiveExec left false
	}

	engine := New(serverTLS)
	done := make(chan error, 1)
	go func() {
		done <- engine.ProxyInject(context.Background(), agentClientEnd, agentUpstreamEnd, resolver, wire.NoopRecorder{})
	}()

	clientTLSConn := tls.Client(clientPlain, &tls.Config{InsecureSkipVerify: true}) //nolint:gosec // test
	req, _ := http.NewRequest(http.MethodPost, "https://cluster/api/v1/namespaces/default/pods/my-pod/exec", nil)
	req.Header.Set("Authorization", "Bearer session-token")
	if err := req.Write(clientTLSConn); err != nil {
		t.Fatalf("write request: %v", err)
	}
	resp, err := http.ReadResponse(bufio.NewReader(clientTLSConn), req)
	if err != nil {
		t.Fatalf("read response: %v", err)
	}
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("expected 403, got %d", resp.StatusCode)
	}
	_ = clientTLSConn.Close()
	<-done
}

// TestProxyInjectAllowsInteractiveExecWhenGranted covers the opt-in path (§11.6): when the resolved
// credential sets AllowInteractiveExec, an exec request is forwarded upstream, its 101 upgrade
// response is relayed verbatim, and the connection becomes a raw bidirectional byte relay
// afterward.
func TestProxyInjectAllowsInteractiveExecWhenGranted(t *testing.T) {
	clientPlain, agentClientEnd := net.Pipe()
	agentUpstreamEnd, upstreamPlain := net.Pipe()
	defer clientPlain.Close()

	serverTLS := selfSignedTLSConfig(t)
	upstreamDone := make(chan struct{})
	var upstreamGotAuth string
	var echoed []byte
	go func() {
		defer close(upstreamDone)
		tconn := tls.Server(upstreamPlain, serverTLS)
		if err := tconn.Handshake(); err != nil {
			return
		}
		defer tconn.Close()
		r := bufio.NewReader(tconn)
		req, err := http.ReadRequest(r)
		if err != nil {
			return
		}
		upstreamGotAuth = req.Header.Get("Authorization")
		_, _ = io.Copy(io.Discard, req.Body)
		_, _ = tconn.Write([]byte("HTTP/1.1 101 Switching Protocols\r\nUpgrade: SPDY/3.1\r\nConnection: Upgrade\r\n\r\n"))
		buf := make([]byte, 5)
		n, _ := io.ReadFull(r, buf)
		echoed = append(echoed, buf[:n]...)
		_, _ = tconn.Write([]byte("output"))
	}()

	resolver := func(ctx context.Context, sessionToken string) (UpstreamCredential, error) {
		return UpstreamCredential{BearerToken: "real-cluster-token", InsecureSkipVerify: true, AllowInteractiveExec: true}, nil
	}

	engine := New(serverTLS)
	done := make(chan error, 1)
	go func() {
		done <- engine.ProxyInject(context.Background(), agentClientEnd, agentUpstreamEnd, resolver, wire.NoopRecorder{})
	}()

	clientTLSConn := tls.Client(clientPlain, &tls.Config{InsecureSkipVerify: true}) //nolint:gosec // test
	req, _ := http.NewRequest(http.MethodPost, "https://cluster/api/v1/namespaces/default/pods/my-pod/exec?command=sh&stdin=true&stdout=true&tty=true", nil)
	req.Header.Set("Authorization", "Bearer session-token")
	req.Header.Set("Upgrade", "SPDY/3.1")
	req.Header.Set("Connection", "Upgrade")
	if err := req.Write(clientTLSConn); err != nil {
		t.Fatalf("write request: %v", err)
	}

	clientReader := bufio.NewReader(clientTLSConn)
	statusLine, err := clientReader.ReadString('\n')
	if err != nil {
		t.Fatalf("read status line: %v", err)
	}
	if !strings.Contains(statusLine, "101") {
		t.Fatalf("expected 101 status line, got %q", statusLine)
	}
	// Drain headers up to the blank line.
	for {
		line, err := clientReader.ReadString('\n')
		if err != nil {
			t.Fatalf("read header line: %v", err)
		}
		if strings.TrimRight(line, "\r\n") == "" {
			break
		}
	}

	if _, err := clientTLSConn.Write([]byte("stdin!")); err != nil {
		t.Fatalf("write stdin: %v", err)
	}
	outBuf := make([]byte, 6)
	if _, err := io.ReadFull(clientReader, outBuf); err != nil {
		t.Fatalf("read exec output: %v", err)
	}
	if string(outBuf) != "output" {
		t.Fatalf("expected relayed output %q, got %q", "output", outBuf)
	}

	_ = clientTLSConn.Close()
	<-upstreamDone
	<-done

	if upstreamGotAuth != "Bearer real-cluster-token" {
		t.Fatalf("expected upstream to see real cluster token, got %q", upstreamGotAuth)
	}
	if string(echoed) != "stdin" {
		t.Fatalf("expected upstream to receive relayed stdin, got %q", echoed)
	}
}
