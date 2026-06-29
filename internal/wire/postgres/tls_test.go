package postgres

import (
	"bufio"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/binary"
	"encoding/pem"
	"io"
	"math/big"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/curlix-io/skybridge/internal/wire"
)

// testTLSConfig builds a server tls.Config with a fresh self-signed cert (mirrors the agent's dev
// cert path) so the engine can terminate client TLS in-process.
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

func writeSSLRequest(t *testing.T, w io.Writer) {
	t.Helper()
	var b [8]byte
	binary.BigEndian.PutUint32(b[0:4], 8)
	binary.BigEndian.PutUint32(b[4:8], sslRequestCode)
	if _, err := w.Write(b[:]); err != nil {
		t.Fatalf("write SSLRequest: %v", err)
	}
}

func TestNegotiateStartupTerminatesClientTLS(t *testing.T) {
	clientEnd, serverEnd := net.Pipe()
	defer clientEnd.Close()
	defer serverEnd.Close()
	deadline(t, clientEnd, serverEnd)

	type result struct {
		params map[string]string
		isTLS  bool
		err    error
	}
	out := make(chan result, 1)
	go func() {
		conn, cr, err := negotiateStartup(serverEnd, testTLSConfig(t))
		if err != nil {
			out <- result{err: err}
			return
		}
		_, isTLS := conn.(*tls.Conn)
		params, err := readStartupParams(cr)
		out <- result{params: params, isTLS: isTLS, err: err}
	}()

	writeSSLRequest(t, clientEnd)
	resp := make([]byte, 1)
	if _, err := io.ReadFull(clientEnd, resp); err != nil {
		t.Fatalf("read SSL response: %v", err)
	}
	if resp[0] != 'S' {
		t.Fatalf("expected 'S' (TLS accepted), got %q", resp[0])
	}
	tconn := tls.Client(clientEnd, &tls.Config{InsecureSkipVerify: true}) //nolint:gosec // test
	if err := tconn.Handshake(); err != nil {
		t.Fatalf("client TLS handshake: %v", err)
	}
	if err := writeStartupMessage(tconn, "alice", "appdb"); err != nil {
		t.Fatalf("startup over TLS: %v", err)
	}

	r := <-out
	if r.err != nil {
		t.Fatalf("negotiate/read: %v", r.err)
	}
	if !r.isTLS {
		t.Fatal("expected the returned conn to be TLS-wrapped")
	}
	if r.params["user"] != "alice" || r.params["database"] != "appdb" {
		t.Fatalf("startup params over TLS = %v", r.params)
	}
}

func TestNegotiateStartupDeclinesSSLWithoutTLS(t *testing.T) {
	clientEnd, serverEnd := net.Pipe()
	defer clientEnd.Close()
	defer serverEnd.Close()
	deadline(t, clientEnd, serverEnd)

	out := make(chan map[string]string, 1)
	go func() {
		conn, cr, err := negotiateStartup(serverEnd, nil)
		if err != nil {
			out <- nil
			return
		}
		if _, isTLS := conn.(*tls.Conn); isTLS {
			out <- nil
			return
		}
		params, _ := readStartupParams(cr)
		out <- params
	}()

	writeSSLRequest(t, clientEnd)
	resp := make([]byte, 1)
	if _, err := io.ReadFull(clientEnd, resp); err != nil {
		t.Fatalf("read SSL response: %v", err)
	}
	if resp[0] != 'N' {
		t.Fatalf("expected 'N' (SSL declined), got %q", resp[0])
	}
	// After the decline the client proceeds in plaintext.
	if err := writeStartupMessage(clientEnd, "bob", "db"); err != nil {
		t.Fatalf("plaintext startup: %v", err)
	}
	params := <-out
	if params == nil || params["user"] != "bob" {
		t.Fatalf("expected plaintext startup user=bob, got %v", params)
	}
}

// TestProxyInjectOverClientTLS is the end-to-end goal of this change: the client speaks TLS to the
// agent (so the session token is encrypted), the agent injects an upstream credential over SCRAM,
// and the result row is masked.
func TestProxyInjectOverClientTLS(t *testing.T) {
	const upstreamPassword = "minted-pw"
	clientEnd, agentClient := net.Pipe()
	agentUpstream, upstreamEnd := net.Pipe()
	defer clientEnd.Close()
	defer agentUpstream.Close()
	deadline(t, clientEnd, agentClient, agentUpstream, upstreamEnd)

	resolve := func(_ context.Context, startup map[string]string, secret string) (wire.UpstreamCredential, error) {
		if secret != "tls-session-token" || startup["user"] != "alice" {
			return wire.UpstreamCredential{}, io.ErrUnexpectedEOF
		}
		return wire.UpstreamCredential{Username: "svc", Password: upstreamPassword}, nil
	}

	engine := NewWithClientTLS(testTLSConfig(t))
	proxyErr := make(chan error, 1)
	go func() {
		proxyErr <- engine.ProxyInject(context.Background(), agentClient, agentUpstream,
			columnMasker{redact: map[string]bool{"email": true}}, resolve)
	}()

	upErr := make(chan error, 1)
	go func() {
		if err := scramServerHandshake(upstreamEnd, upstreamPassword); err != nil {
			upErr <- err
			return
		}
		writeMsg(t, upstreamEnd, 'T', rowDescriptionPayload("id", "email"))
		writeMsg(t, upstreamEnd, 'D', dataRowPayload([]byte("1"), []byte("alice@example.com")))
		writeMsg(t, upstreamEnd, 'Z', []byte{'I'})
		upErr <- nil
	}()

	// Client: SSLRequest -> 'S' -> TLS -> startup -> token over the encrypted channel.
	writeSSLRequest(t, clientEnd)
	resp := make([]byte, 1)
	if _, err := io.ReadFull(clientEnd, resp); err != nil || resp[0] != 'S' {
		t.Fatalf("SSL negotiation: resp=%q err=%v", resp, err)
	}
	tconn := tls.Client(clientEnd, &tls.Config{InsecureSkipVerify: true}) //nolint:gosec // test
	if err := tconn.Handshake(); err != nil {
		t.Fatalf("client TLS handshake: %v", err)
	}
	if err := writeStartupMessage(tconn, "alice", "appdb"); err != nil {
		t.Fatalf("startup: %v", err)
	}
	cr := bufio.NewReader(tconn)
	typ, payload, err := readBackendMessage(cr)
	if err != nil || typ != msgAuthentication || binary.BigEndian.Uint32(payload[0:4]) != authCleartextPassword {
		t.Fatalf("expected cleartext password request over TLS: typ=%q err=%v", string(rune(typ)), err)
	}
	if err := writePasswordMessage(tconn, "tls-session-token"); err != nil {
		t.Fatalf("send token: %v", err)
	}

	var masked, plaintext bool
	for i := 0; i < 5; i++ {
		typ, payload, err = readBackendMessage(cr)
		if err != nil {
			break
		}
		if typ == 'D' {
			if strings.Contains(string(payload), "***") {
				masked = true
			}
			if strings.Contains(string(payload), "alice@example.com") {
				plaintext = true
			}
		}
		if typ == 'Z' {
			break
		}
	}
	if err := <-upErr; err != nil {
		t.Fatalf("upstream harness: %v", err)
	}
	if !masked {
		t.Fatal("expected the email column masked over the TLS session")
	}
	if plaintext {
		t.Fatal("plaintext email leaked over the TLS session")
	}
}
