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

func TestProxyInjectRejectsInteractiveSubresource(t *testing.T) {
	clientPlain, agentClientEnd := net.Pipe()
	_, agentUpstreamEnd := net.Pipe()
	defer clientPlain.Close()

	serverTLS := selfSignedTLSConfig(t)
	resolver := func(ctx context.Context, sessionToken string) (UpstreamCredential, error) {
		t.Fatal("resolver should not be called for a blocked path")
		return UpstreamCredential{}, nil
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
