package mongo

import (
	"bufio"
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/binary"
	"encoding/pem"
	"math/big"
	"net"
	"testing"
	"time"

	"github.com/curlix-io/skybridge/internal/mask"
	"github.com/curlix-io/skybridge/internal/wire"
)

// testTLSConfig builds a server tls.Config with a fresh self-signed cert (mirrors the agent's dev
// cert path and postgres/tls_test.go's helper of the same name) so the engine can terminate client
// TLS in-process.
func testTLSConfig(t *testing.T) *tls.Config {
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

func TestNewWithClientTLS_TerminatesClientTLSBeforeWireProtocol(t *testing.T) {
	clientConn, engineClient := net.Pipe()
	engineUpstream, upstreamConn := net.Pipe()
	defer clientConn.Close()
	defer engineUpstream.Close()
	dl := time.Now().Add(8 * time.Second)
	for _, c := range []net.Conn{clientConn, engineClient, engineUpstream, upstreamConn} {
		_ = c.SetDeadline(dl)
	}

	engine := NewWithClientTLS(testTLSConfig(t)).WithOrgID("org1")
	overlay := mask.NewOverlay(map[string]string{"email": "[redacted]"})

	proxyErr := make(chan error, 1)
	go func() {
		proxyErr <- engine.Proxy(context.Background(), engineClient, engineUpstream, overlay, wire.NoopRecorder{})
	}()

	upstreamDone := make(chan error, 1)
	go func() {
		br := bufio.NewReader(upstreamConn)
		msg, err := readMessage(br)
		if err != nil {
			upstreamDone <- err
			return
		}
		requestID := int32(binary.LittleEndian.Uint32(msg[4:8]))
		reply := opMsgReplyTo(findReplyBody(), requestID)
		if _, err := upstreamConn.Write(reply); err != nil {
			upstreamDone <- err
			return
		}
		upstreamDone <- nil
	}()

	// Mongo has no in-band STARTTLS — the client must speak TLS immediately, unlike Postgres's
	// SSLRequest negotiation frame.
	tconn := tls.Client(clientConn, &tls.Config{InsecureSkipVerify: true}) //nolint:gosec // test
	if err := tconn.Handshake(); err != nil {
		t.Fatalf("client TLS handshake: %v", err)
	}

	req := opMsgRequest(findCommand("orders", "shop"), 99)
	if _, err := tconn.Write(req); err != nil {
		t.Fatalf("client write request over TLS: %v", err)
	}

	cr := bufio.NewReader(tconn)
	out, err := readMessage(cr)
	if err != nil {
		t.Fatalf("client read reply over TLS: %v", err)
	}
	if bytes.Contains(out, []byte("alice@example.com")) {
		t.Fatal("email leaked through Proxy over TLS")
	}
	if !bytes.Contains(out, []byte("[redacted]")) {
		t.Fatal("masking not applied through Proxy over TLS")
	}

	if err := <-upstreamDone; err != nil {
		t.Fatalf("upstream harness: %v", err)
	}
	_ = clientConn.Close()
	select {
	case <-proxyErr:
	case <-time.After(5 * time.Second):
		t.Fatal("Proxy did not return after client closed")
	}
}

func TestNewWithClientTLS_RejectsPlaintextClient(t *testing.T) {
	clientConn, engineClient := net.Pipe()
	engineUpstream, upstreamConn := net.Pipe()
	defer clientConn.Close()
	defer upstreamConn.Close()
	dl := time.Now().Add(3 * time.Second)
	for _, c := range []net.Conn{clientConn, engineClient, engineUpstream, upstreamConn} {
		_ = c.SetDeadline(dl)
	}

	engine := NewWithClientTLS(testTLSConfig(t))
	proxyErr := make(chan error, 1)
	go func() {
		proxyErr <- engine.Proxy(context.Background(), engineClient, engineUpstream, mask.Noop{}, wire.NoopRecorder{})
	}()

	// A plaintext client sending wire bytes directly (no TLS handshake) must fail the handshake,
	// not be silently accepted as plaintext — Mongo has no SSL-decline fallback like Postgres's 'N'.
	req := opMsgRequest(findCommand("orders", "shop"), 1)
	_, _ = clientConn.Write(req)
	_ = clientConn.Close()

	select {
	case err := <-proxyErr:
		if err == nil {
			t.Fatal("expected Proxy to fail the TLS handshake against a plaintext client, got nil error")
		}
	case <-time.After(5 * time.Second):
		t.Fatal("Proxy did not return for a plaintext client against a TLS-only engine")
	}
}

func TestNew_NoClientTLSStillWorksPlaintext(t *testing.T) {
	engine := New()
	if engine.clientTLS != nil {
		t.Fatal("New() must not configure client TLS")
	}
}
