package mysql

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
	"errors"
	"fmt"
	"math/big"
	"net"
	"testing"
	"time"

	"github.com/curlix-io/skybridge/internal/mask"
)

func testServerTLS(t *testing.T) *tls.Config {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("key: %v", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "skybridge-mysql-test"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		DNSNames:     []string{"localhost"},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("cert: %v", err)
	}
	keyDER, _ := x509.MarshalECPrivateKey(key)
	cert, err := tls.X509KeyPair(
		pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}),
		pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER}),
	)
	if err != nil {
		t.Fatalf("keypair: %v", err)
	}
	return &tls.Config{Certificates: []tls.Certificate{cert}, MinVersion: tls.VersionTLS12}
}

// buildGreeting assembles a minimal v10 Initial Handshake packet body. lowerCaps controls the
// advertised capability flags (set CLIENT_SSL to make the server "support" TLS).
func buildGreeting(lowerCaps uint16) []byte {
	g := []byte{0x0a} // protocol version 10
	g = append(g, "8.0.0"...)
	g = append(g, 0)                                   // version cstring NUL
	g = append(g, 1, 0, 0, 0)                          // connection id
	g = append(g, 1, 2, 3, 4, 5, 6, 7, 8)              // auth-plugin-data-part-1
	g = append(g, 0)                                   // filler
	g = append(g, byte(lowerCaps), byte(lowerCaps>>8)) // capability flags (lower)
	g = append(g, 0x21)                                // charset
	g = append(g, 0, 0)                                // status flags
	g = append(g, 0, 0)                                // capability flags (upper)
	g = append(g, 0)                                   // auth-plugin-data length
	g = append(g, make([]byte, 10)...)                 // reserved
	g = append(g, make([]byte, 13)...)                 // auth-plugin-data-part-2
	return g
}

func okPacket() []byte {
	return []byte{pktOK, 0x00, 0x00, 0x02, 0x00, 0x00, 0x00} // header, rows, id, status, warnings
}

func TestServerSupportsSSL(t *testing.T) {
	if !serverSupportsSSL(buildGreeting(capClientSSL | capClientProtocol41)) {
		t.Fatal("expected SSL support when CLIENT_SSL is advertised")
	}
	if serverSupportsSSL(buildGreeting(capClientProtocol41)) {
		t.Fatal("did not expect SSL support without CLIENT_SSL")
	}
	if serverSupportsSSL([]byte{0x09, 0x00}) {
		t.Fatal("non-v10 greeting must not report SSL support")
	}
}

// TestProxyUpstreamTLSMasksOverEncryptedLink is the end-to-end goal: the agent inserts an SSL-request
// packet, negotiates TLS with the upstream, shifts the connection-phase sequence ids by +1, and then
// masks a result set delivered over the encrypted link — while the client link stays plaintext.
func TestProxyUpstreamTLSMasksOverEncryptedLink(t *testing.T) {
	clientConn, engineClient := net.Pipe()
	engineUpstream, upstreamConn := net.Pipe()
	defer clientConn.Close()
	defer engineUpstream.Close()
	dl := time.Now().Add(8 * time.Second)
	for _, c := range []net.Conn{clientConn, engineClient, engineUpstream, upstreamConn} {
		_ = c.SetDeadline(dl)
	}

	overlay := mask.NewOverlay(map[string]string{"email": "[redacted]"})
	engine := New().WithUpstreamTLS(&tls.Config{InsecureSkipVerify: true}, true) //nolint:gosec // test

	proxyErr := make(chan error, 1)
	go func() {
		proxyErr <- engine.Proxy(context.Background(), engineClient, engineUpstream, overlay)
	}()

	upErr := make(chan error, 1)
	go func() { upErr <- runFakeUpstreamTLS(upstreamConn, testServerTLS(t)) }()

	cr := bufio.NewReader(clientConn)
	if _, _, _, err := readPacket(cr); err != nil { // greeting
		t.Fatalf("client read greeting: %v", err)
	}
	// HandshakeResponse (seq 1): PROTOCOL_41, no CLIENT_SSL, ≥32 bytes so the agent can build an SSL request.
	resp := make([]byte, 40)
	binary.LittleEndian.PutUint32(resp[0:4], capClientProtocol41)
	if _, err := clientConn.Write(pkt(1, resp)); err != nil {
		t.Fatalf("client send handshake response: %v", err)
	}
	// The auth result must arrive as seq 2 from the client's view (server seq 3 − offset 1).
	okSeq, okPayload, _, err := readPacket(cr)
	if err != nil {
		t.Fatalf("client read auth result: %v", err)
	}
	if okSeq != 2 {
		t.Fatalf("auth result seq = %d, want 2 (sequence offset not applied)", okSeq)
	}
	if len(okPayload) == 0 || okPayload[0] != pktOK {
		t.Fatalf("expected OK auth result, got %v", okPayload)
	}
	// Command phase: COM_QUERY (seq 0) → masked result set.
	if _, err := clientConn.Write(pkt(0, append([]byte{comQuery}, "SELECT id,email FROM t"...))); err != nil {
		t.Fatalf("client send query: %v", err)
	}
	var got bytes.Buffer
	colCountSeq, payload, _, err := readPacket(cr)
	if err != nil {
		t.Fatalf("client read column count: %v", err)
	}
	if colCountSeq != 1 {
		t.Fatalf("column-count seq = %d, want 1 (offset must be 0 in the command phase)", colCountSeq)
	}
	got.Write(pkt(colCountSeq, payload))
	for i := 0; i < 5; i++ { // 2 col defs, EOF, 1 row, terminating EOF
		s, p, _, err := readPacket(cr)
		if err != nil {
			t.Fatalf("client read result packet %d: %v", i, err)
		}
		got.Write(pkt(s, p))
	}

	if bytes.Contains(got.Bytes(), []byte("alice@example.com")) {
		t.Fatal("email leaked in cleartext over the masked TLS session")
	}
	if bytes.Count(got.Bytes(), []byte("[redacted]")) != 1 {
		t.Fatalf("expected exactly one redaction, got %d", bytes.Count(got.Bytes(), []byte("[redacted]")))
	}
	if err := <-upErr; err != nil {
		t.Fatalf("upstream harness: %v", err)
	}
}

// runFakeUpstreamTLS plays a MySQL server that requires the agent to negotiate TLS in-handshake.
func runFakeUpstreamTLS(conn net.Conn, tlsCfg *tls.Config) error {
	if _, err := conn.Write(pkt(0, buildGreeting(capClientSSL|capClientProtocol41))); err != nil {
		return err
	}
	br := bufio.NewReader(conn)
	seq, payload, _, err := readPacket(br) // SSL request (seq 1)
	if err != nil {
		return err
	}
	if seq != 1 {
		return fmt.Errorf("SSL request seq = %d, want 1", seq)
	}
	if len(payload) < 4 || binary.LittleEndian.Uint32(payload[0:4])&capClientSSL == 0 {
		return errors.New("SSL request did not set CLIENT_SSL")
	}
	srv := tls.Server(conn, tlsCfg)
	if err := srv.Handshake(); err != nil {
		return fmt.Errorf("upstream TLS handshake: %w", err)
	}
	sbr := bufio.NewReader(srv)
	if seq, _, _, err = readPacket(sbr); err != nil { // full HandshakeResponse (seq 2)
		return err
	}
	if seq != 2 {
		return fmt.Errorf("HandshakeResponse seq = %d, want 2", seq)
	}
	if _, err := srv.Write(pkt(3, okPacket())); err != nil { // auth OK (seq 3)
		return err
	}
	if seq, payload, _, err = readPacket(sbr); err != nil { // COM_QUERY (seq 0)
		return err
	}
	if seq != 0 || len(payload) == 0 || payload[0] != comQuery {
		return fmt.Errorf("expected COM_QUERY at seq 0, got seq %d", seq)
	}
	for _, p := range [][]byte{
		pkt(1, []byte{0x02}),
		pkt(2, colDef("id")),
		pkt(3, colDef("email")),
		pkt(4, eofPacket()),
		pkt(5, textRow("1", "alice@example.com")),
		pkt(6, eofPacket()),
	} {
		if _, err := srv.Write(p); err != nil {
			return err
		}
	}
	return nil
}

// TestProxyUpstreamTLSRequiredButServerLacksSSL: when the upstream does not advertise SSL and TLS is
// required, the session fails rather than silently falling back to plaintext.
func TestProxyUpstreamTLSRequiredButServerLacksSSL(t *testing.T) {
	clientConn, engineClient := net.Pipe()
	engineUpstream, upstreamConn := net.Pipe()
	defer clientConn.Close()
	defer engineUpstream.Close()
	dl := time.Now().Add(5 * time.Second)
	for _, c := range []net.Conn{clientConn, engineClient, engineUpstream, upstreamConn} {
		_ = c.SetDeadline(dl)
	}

	engine := New().WithUpstreamTLS(&tls.Config{InsecureSkipVerify: true}, true) //nolint:gosec // test
	proxyErr := make(chan error, 1)
	go func() {
		proxyErr <- engine.Proxy(context.Background(), engineClient, engineUpstream, mask.Noop{})
	}()

	// Upstream greeting WITHOUT CLIENT_SSL.
	go func() { _, _ = upstreamConn.Write(pkt(0, buildGreeting(capClientProtocol41))) }()

	cr := bufio.NewReader(clientConn)
	if _, _, _, err := readPacket(cr); err != nil {
		t.Fatalf("client read greeting: %v", err)
	}
	resp := make([]byte, 40)
	binary.LittleEndian.PutUint32(resp[0:4], capClientProtocol41)
	if _, err := clientConn.Write(pkt(1, resp)); err != nil {
		t.Fatalf("client send handshake response: %v", err)
	}
	select {
	case err := <-proxyErr:
		if err == nil {
			t.Fatal("expected an error when upstream TLS is required but unavailable")
		}
	case <-time.After(5 * time.Second):
		t.Fatal("Proxy did not return after required upstream TLS was unavailable")
	}
}
