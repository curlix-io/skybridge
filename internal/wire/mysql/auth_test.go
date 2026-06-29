package mysql

import (
	"bufio"
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha1" //nolint:gosec // verifying the mysql_native_password scramble requires SHA1
	"crypto/tls"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/curlix-io/skybridge/internal/mask"
	"github.com/curlix-io/skybridge/internal/wire"
)

// verifyNativeScramble performs the server-side check of a mysql_native_password response.
func verifyNativeScramble(password string, nonce, scramble []byte) bool {
	if password == "" {
		return len(scramble) == 0
	}
	if len(scramble) != sha1.Size {
		return false
	}
	h1 := sha1.Sum([]byte(password))
	h2 := sha1.Sum(h1[:])
	h := sha1.New()
	h.Write(nonce)
	h.Write(h2[:])
	token := h.Sum(nil)
	cand := make([]byte, len(scramble))
	for i := range scramble {
		cand[i] = scramble[i] ^ token[i]
	}
	return sha1.Sum(cand) == h2
}

func TestNativePasswordScrambleVerifies(t *testing.T) {
	nonce := make([]byte, 20)
	if _, err := rand.Read(nonce); err != nil {
		t.Fatal(err)
	}
	scramble := nativePasswordScramble("s3cret", nonce)
	if !verifyNativeScramble("s3cret", nonce, scramble) {
		t.Fatal("server-side verification of the native scramble failed")
	}
	if verifyNativeScramble("wrong", nonce, scramble) {
		t.Fatal("verification must fail for the wrong password")
	}
	if nativePasswordScramble("", nonce) != nil {
		t.Fatal("empty password must produce an empty scramble")
	}
}

func TestCachingSha2ScrambleShape(t *testing.T) {
	nonce := make([]byte, 20)
	a := cachingSha2Scramble("pw", nonce)
	b := cachingSha2Scramble("pw", nonce)
	if len(a) != 32 || !bytes.Equal(a, b) {
		t.Fatalf("caching_sha2 scramble should be 32 deterministic bytes, got %d", len(a))
	}
	if cachingSha2Scramble("", nonce) != nil {
		t.Fatal("empty password must produce an empty scramble")
	}
}

func TestCompleteUpstreamAuthFullAuthRequiresTLS(t *testing.T) {
	var buf bytes.Buffer
	buf.Write(pkt(2, []byte{authMoreData, cachingSha2FullAuth}))
	err := completeUpstreamAuth(io.Discard, bufio.NewReader(&buf), "pw", make([]byte, 20), false)
	if err == nil || !strings.Contains(err.Error(), "requires upstream TLS") {
		t.Fatalf("expected a 'requires upstream TLS' error, got %v", err)
	}
}

// makeServerGreeting builds a v10 Initial Handshake advertising plugin and (optionally) CLIENT_SSL.
func makeServerGreeting(nonce []byte, plugin string, ssl bool) []byte {
	capLower := uint16(capClientProtocol41 | capSecureConnection)
	if ssl {
		capLower |= capClientSSL
	}
	capUpper := uint16(capPluginAuth >> 16)
	var b []byte
	b = append(b, 0x0a)
	b = append(b, "8.0.0-test"...)
	b = append(b, 0)
	b = append(b, 9, 0, 0, 0)
	b = append(b, nonce[:8]...)
	b = append(b, 0)
	b = append(b, byte(capLower), byte(capLower>>8))
	b = append(b, 0x21)
	b = append(b, 0x02, 0x00)
	b = append(b, byte(capUpper), byte(capUpper>>8))
	b = append(b, byte(len(nonce)+1))
	b = append(b, make([]byte, 10)...)
	b = append(b, nonce[8:20]...)
	b = append(b, 0)
	b = append(b, plugin...)
	b = append(b, 0)
	return b
}

// clientHandshakeResp is a minimal PROTOCOL_41 + SECURE_CONNECTION response (username "client", dummy
// native scramble, no database). CLIENT_SSL is added when the client tunnels through TLS.
func clientHandshakeResp(ssl bool) []byte {
	caps := uint32(capClientProtocol41 | capSecureConnection)
	if ssl {
		caps |= capClientSSL
	}
	var b []byte
	var c [4]byte
	binary.LittleEndian.PutUint32(c[:], caps)
	b = append(b, c[:]...)
	b = append(b, make([]byte, 4)...)  // max packet
	b = append(b, 0x21)                // charset
	b = append(b, make([]byte, 23)...) // reserved
	b = append(b, "client"...)
	b = append(b, 0)
	b = append(b, 20)                  // auth-response length
	b = append(b, make([]byte, 20)...) // dummy native scramble (ignored; we switch to cleartext)
	return b
}

// authRespFromHandshake extracts the 1-byte-length-prefixed auth response that follows the username.
func authRespFromHandshake(p []byte) []byte {
	_, off, ok := readNulString(p, 32)
	if !ok || off >= len(p) {
		return nil
	}
	l := int(p[off])
	off++
	if off+l > len(p) {
		return nil
	}
	return p[off : off+l]
}

// runInjectUpstream plays the upstream MySQL server for an injected login, then serves one masked
// result set. password is the credential the agent should present; plugin/flow pick the auth method.
func runInjectUpstream(conn net.Conn, plugin, flow, password string) error {
	nonce := make([]byte, 20)
	if _, err := rand.Read(nonce); err != nil {
		return err
	}
	greeting := makeServerGreeting(nonce, plugin, false)
	if _, err := conn.Write(pkt(0, greeting)); err != nil {
		return err
	}
	parsedNonce, _, _ := parseServerGreeting(greeting)
	br := bufio.NewReader(conn)
	hseq, hpayload, _, err := readPacket(br)
	if err != nil {
		return err
	}
	info := parseHandshakeResponse(hpayload, binary.LittleEndian.Uint32(hpayload[:4]))
	if info.username != "appuser" {
		return errTest("upstream username = %q, want appuser", info.username)
	}
	if plugin == pluginNativePassword {
		if !verifyNativeScramble(password, parsedNonce, authRespFromHandshake(hpayload)) {
			return errTest("native scramble did not verify")
		}
	}
	switch flow {
	case "ok":
		if _, err := conn.Write(pkt(hseq+1, okPayload())); err != nil {
			return err
		}
	case "fast":
		if _, err := conn.Write(pkt(hseq+1, []byte{authMoreData, cachingSha2FastAuthSuccess})); err != nil {
			return err
		}
		if _, err := conn.Write(pkt(hseq+2, okPayload())); err != nil {
			return err
		}
	}
	// Command phase: one COM_QUERY → a result set with an "email" column to be masked.
	qseq, q, _, err := readPacket(br)
	if err != nil {
		return err
	}
	if qseq != 0 || len(q) == 0 || q[0] != comQuery {
		return errTest("expected COM_QUERY at seq 0")
	}
	for _, p := range [][]byte{
		pkt(1, []byte{0x01}),
		pkt(2, colDef("email")),
		pkt(3, eofPacket()),
		pkt(4, textRow("alice@example.com")),
		pkt(5, eofPacket()),
	} {
		if _, err := conn.Write(p); err != nil {
			return err
		}
	}
	return nil
}

func errTest(format string, a ...any) error { return fmt.Errorf(format, a...) }

func runInjectScenario(t *testing.T, plugin, flow string, clientTLS bool) {
	t.Helper()
	clientConn, engineClient := net.Pipe()
	engineUpstream, upstreamConn := net.Pipe()
	defer clientConn.Close()
	defer engineUpstream.Close()
	dl := time.Now().Add(8 * time.Second)
	for _, c := range []net.Conn{clientConn, engineClient, engineUpstream, upstreamConn} {
		_ = c.SetDeadline(dl)
	}

	var serverTLS *tls.Config
	engine := New()
	if clientTLS {
		serverTLS = testServerTLS(t)
		engine = NewWithClientTLS(serverTLS)
	}
	overlay := mask.NewOverlay(map[string]string{"email": "[redacted]"})
	resolve := func(_ context.Context, startup map[string]string, secret string) (wire.UpstreamCredential, error) {
		if secret != "tok-123" {
			return wire.UpstreamCredential{}, errTest("resolver got token %q", secret)
		}
		return wire.UpstreamCredential{Username: "appuser", Password: "s3cret"}, nil
	}

	proxyErr := make(chan error, 1)
	go func() {
		proxyErr <- engine.ProxyInject(context.Background(), engineClient, engineUpstream, overlay, resolve)
	}()
	upErr := make(chan error, 1)
	go func() { upErr <- runInjectUpstream(upstreamConn, plugin, flow, "s3cret") }()

	conn := net.Conn(clientConn)
	cr := bufio.NewReader(conn)
	if _, _, _, err := readPacket(cr); err != nil { // greeting
		t.Fatalf("client read greeting: %v", err)
	}
	if clientTLS {
		caps := uint32(capClientProtocol41 | capSecureConnection | capClientSSL)
		ssl := make([]byte, sslRequestLen)
		binary.LittleEndian.PutUint32(ssl[0:4], caps)
		ssl[8] = 0x21
		if _, err := conn.Write(pkt(1, ssl)); err != nil {
			t.Fatalf("client SSL request: %v", err)
		}
		tc := tls.Client(conn, &tls.Config{InsecureSkipVerify: true}) //nolint:gosec // test
		if err := tc.Handshake(); err != nil {
			t.Fatalf("client TLS handshake: %v", err)
		}
		conn = tc
		cr = bufio.NewReader(tc)
		if _, err := conn.Write(pkt(2, clientHandshakeResp(true))); err != nil {
			t.Fatalf("client handshake response: %v", err)
		}
	} else if _, err := conn.Write(pkt(1, clientHandshakeResp(false))); err != nil {
		t.Fatalf("client handshake response: %v", err)
	}

	swSeq, sw, _, err := readPacket(cr)
	if err != nil {
		t.Fatalf("client read auth switch: %v", err)
	}
	plug, _ := parseAuthSwitch(sw)
	if sw[0] != authSwitchRequest || plug != pluginClearPassword {
		t.Fatalf("expected auth switch to %s, got %q", pluginClearPassword, plug)
	}
	if _, err := conn.Write(pkt(swSeq+1, append([]byte("tok-123"), 0))); err != nil {
		t.Fatalf("client send token: %v", err)
	}
	okSeq, okPayload, _, err := readPacket(cr)
	if err != nil {
		t.Fatalf("client read OK: %v", err)
	}
	if len(okPayload) == 0 || okPayload[0] != pktOK {
		t.Fatalf("expected OK after injected auth, got %v (seq %d)", okPayload, okSeq)
	}

	if _, err := conn.Write(pkt(0, append([]byte{comQuery}, "SELECT email FROM t"...))); err != nil {
		t.Fatalf("client send query: %v", err)
	}
	var got bytes.Buffer
	for i := 0; i < 5; i++ {
		s, p, _, err := readPacket(cr)
		if err != nil {
			t.Fatalf("client read result packet %d: %v", i, err)
		}
		got.Write(pkt(s, p))
	}
	if bytes.Contains(got.Bytes(), []byte("alice@example.com")) {
		t.Fatal("email leaked through the injected, masked session")
	}
	if bytes.Count(got.Bytes(), []byte("[redacted]")) != 1 {
		t.Fatalf("expected one redaction, got %d", bytes.Count(got.Bytes(), []byte("[redacted]")))
	}
	if err := <-upErr; err != nil {
		t.Fatalf("upstream harness: %v", err)
	}
}

func TestProxyInjectNativePasswordEndToEnd(t *testing.T) {
	runInjectScenario(t, pluginNativePassword, "ok", false)
}

func TestProxyInjectCachingSha2FastAuth(t *testing.T) {
	runInjectScenario(t, pluginCachingSha2, "fast", false)
}

func TestProxyInjectClientTLSTermination(t *testing.T) {
	runInjectScenario(t, pluginNativePassword, "ok", true)
}
