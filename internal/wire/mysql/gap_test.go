package mysql

import (
	"bufio"
	"bytes"
	"context"
	"crypto/rand"
	"crypto/tls"
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/curlix-io/skybridge/internal/mask"
	"github.com/curlix-io/skybridge/internal/wire"
)

// limitWriter succeeds for the first n bytes written (across all calls) then fails — used to force
// a write/flush failure partway through a multi-write sequence without a real broken connection.
type limitWriter struct{ n int }

func (w *limitWriter) Write(p []byte) (int, error) {
	if w.n <= 0 {
		return 0, errors.New("limitWriter: exhausted")
	}
	if len(p) > w.n {
		n := w.n
		w.n = 0
		return n, errors.New("limitWriter: short write")
	}
	w.n -= len(p)
	return len(p), nil
}

func deadlineAll(t *testing.T, conns ...net.Conn) {
	t.Helper()
	dl := time.Now().Add(8 * time.Second)
	for _, c := range conns {
		_ = c.SetDeadline(dl)
	}
}

// ---- authenticateUpstream: TLS branches and error paths not covered by the ProxyInject scenarios
// (those all run with a nil upstreamTLS) ----

func TestAuthenticateUpstream_TLSRequiredButServerLacksSSL(t *testing.T) {
	client, server := net.Pipe()
	defer client.Close()
	defer server.Close()
	deadlineAll(t, client, server)

	go func() {
		nonce := make([]byte, 20)
		greeting := makeServerGreeting(nonce, pluginNativePassword, false) // no CLIENT_SSL
		_, _ = server.Write(pkt(0, greeting))
	}()

	_, _, err := authenticateUpstream(client, wire.UpstreamCredential{Username: "u", Password: "p"}, "db", &tls.Config{InsecureSkipVerify: true}, true) //nolint:gosec // test
	if err == nil || !strings.Contains(err.Error(), "does not advertise CLIENT_SSL") {
		t.Fatalf("got %v", err)
	}
}

func TestAuthenticateUpstream_UnsupportedPluginErrors(t *testing.T) {
	client, server := net.Pipe()
	defer client.Close()
	defer server.Close()
	deadlineAll(t, client, server)

	go func() {
		nonce := make([]byte, 20)
		greeting := makeServerGreeting(nonce, "sha256_password", false) // unsupported by authResponse
		_, _ = server.Write(pkt(0, greeting))
	}()

	_, _, err := authenticateUpstream(client, wire.UpstreamCredential{Username: "u", Password: "p"}, "db", nil, false)
	if err == nil || !strings.Contains(err.Error(), "unsupported upstream auth plugin") {
		t.Fatalf("got %v", err)
	}
}

func TestAuthenticateUpstream_HandshakeResponseWriteFailure(t *testing.T) {
	client, server := net.Pipe()
	defer client.Close()
	deadlineAll(t, client, server)

	go func() {
		nonce := make([]byte, 20)
		greeting := makeServerGreeting(nonce, pluginNativePassword, false)
		_, _ = server.Write(pkt(0, greeting))
		_ = server.Close() // closed before the agent can write its HandshakeResponse
	}()

	_, _, err := authenticateUpstream(client, wire.UpstreamCredential{Username: "u", Password: "p"}, "db", nil, false)
	if err == nil {
		t.Fatal("expected an error once the server side closes before the handshake response is written")
	}
}

// runFakeUpstreamTLSForAuth plays a MySQL server that requires upstream TLS negotiated by
// authenticateUpstream directly (as opposed to Engine.startUpstreamTLS's connection-phase variant).
func runFakeUpstreamTLSForAuth(conn net.Conn, tlsCfg *tls.Config, password string) error {
	nonce := make([]byte, 20)
	if _, err := rand.Read(nonce); err != nil {
		return err
	}
	greeting := makeServerGreeting(nonce, pluginNativePassword, true)
	if _, err := conn.Write(pkt(0, greeting)); err != nil {
		return err
	}
	br := bufio.NewReader(conn)
	seq, payload, _, err := readPacket(br) // SSL request, seq 1
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
	seq, hpayload, _, err := readPacket(sbr) // full HandshakeResponse, seq 2
	if err != nil {
		return err
	}
	if seq != 2 {
		return fmt.Errorf("HandshakeResponse seq = %d, want 2", seq)
	}
	parsedNonce, _, _ := parseServerGreeting(greeting)
	if !verifyNativeScramble(password, parsedNonce, authRespFromHandshake(hpayload)) {
		return errors.New("scramble did not verify")
	}
	if _, err := srv.Write(pkt(3, okPacket())); err != nil {
		return err
	}
	return nil
}

func TestAuthenticateUpstream_TLSNegotiatesAndCompletesAuth(t *testing.T) {
	agentConn, dbConn := net.Pipe()
	defer agentConn.Close()
	defer dbConn.Close()
	deadlineAll(t, agentConn, dbConn)

	errc := make(chan error, 1)
	go func() { errc <- runFakeUpstreamTLSForAuth(dbConn, testServerTLS(t), "s3cret") }()

	upstream, sb, err := authenticateUpstream(agentConn, wire.UpstreamCredential{Username: "svc", Password: "s3cret"}, "appdb", &tls.Config{InsecureSkipVerify: true}, true) //nolint:gosec // test
	if err != nil {
		t.Fatalf("authenticateUpstream: %v", err)
	}
	if upstream == nil || sb == nil {
		t.Fatal("expected non-nil upstream conn and reader on success")
	}
	if err := <-errc; err != nil {
		t.Fatalf("server harness: %v", err)
	}
}

// ---- ProxyInject: rejection paths (resolver failure, upstream auth failure) ----

func TestProxyInject_ResolveFailureRejectsClient(t *testing.T) {
	clientConn, engineClient := net.Pipe()
	engineUpstream, upstreamConn := net.Pipe()
	defer clientConn.Close()
	defer engineUpstream.Close()
	deadlineAll(t, clientConn, engineClient, engineUpstream, upstreamConn)

	engine := New()
	resolve := func(_ context.Context, _ map[string]string, _ string) (wire.UpstreamCredential, error) {
		return wire.UpstreamCredential{}, errors.New("denied")
	}
	proxyErr := make(chan error, 1)
	go func() {
		proxyErr <- engine.ProxyInject(context.Background(), engineClient, engineUpstream, mask.Noop{}, resolve, wire.NoopRecorder{})
	}()

	cr := bufio.NewReader(clientConn)
	if _, _, _, err := readPacket(cr); err != nil { // greeting
		t.Fatalf("greeting: %v", err)
	}
	if _, err := clientConn.Write(pkt(1, clientHandshakeResp(false))); err != nil {
		t.Fatalf("handshake response: %v", err)
	}
	swSeq, sw, _, err := readPacket(cr) // auth switch
	if err != nil {
		t.Fatalf("auth switch: %v", err)
	}
	if sw[0] != authSwitchRequest {
		t.Fatalf("expected an auth switch request")
	}
	if _, err := clientConn.Write(pkt(swSeq+1, append([]byte("bad-token"), 0))); err != nil {
		t.Fatalf("token: %v", err)
	}
	_, errPayload, _, err := readPacket(cr)
	if err != nil {
		t.Fatalf("read error packet: %v", err)
	}
	if len(errPayload) == 0 || errPayload[0] != pktERR {
		t.Fatalf("expected an ERR packet to the client, got %v", errPayload)
	}
	if err := <-proxyErr; err == nil {
		t.Fatal("expected ProxyInject to return the resolver's error")
	}
}

func TestProxyInject_UpstreamAuthFailureRejectsClient(t *testing.T) {
	clientConn, engineClient := net.Pipe()
	engineUpstream, upstreamConn := net.Pipe()
	defer clientConn.Close()
	defer engineUpstream.Close()
	deadlineAll(t, clientConn, engineClient, engineUpstream, upstreamConn)

	engine := New()
	resolve := func(_ context.Context, _ map[string]string, _ string) (wire.UpstreamCredential, error) {
		return wire.UpstreamCredential{Username: "appuser", Password: "s3cret"}, nil
	}
	proxyErr := make(chan error, 1)
	go func() {
		proxyErr <- engine.ProxyInject(context.Background(), engineClient, engineUpstream, mask.Noop{}, resolve, wire.NoopRecorder{})
	}()

	upErr := make(chan error, 1)
	go func() {
		nonce := make([]byte, 20)
		if _, err := rand.Read(nonce); err != nil {
			upErr <- err
			return
		}
		greeting := makeServerGreeting(nonce, pluginNativePassword, false)
		if _, err := upstreamConn.Write(pkt(0, greeting)); err != nil {
			upErr <- err
			return
		}
		br := bufio.NewReader(upstreamConn)
		hseq, _, _, err := readPacket(br)
		if err != nil {
			upErr <- err
			return
		}
		errPayload := []byte{pktERR, 0x15, 0x04, '#'}
		errPayload = append(errPayload, "28000"...)
		errPayload = append(errPayload, "denied"...)
		_, err = upstreamConn.Write(pkt(hseq+1, errPayload))
		upErr <- err
	}()

	cr := bufio.NewReader(clientConn)
	if _, _, _, err := readPacket(cr); err != nil {
		t.Fatalf("greeting: %v", err)
	}
	if _, err := clientConn.Write(pkt(1, clientHandshakeResp(false))); err != nil {
		t.Fatalf("handshake response: %v", err)
	}
	swSeq, _, _, err := readPacket(cr)
	if err != nil {
		t.Fatalf("auth switch: %v", err)
	}
	if _, err := clientConn.Write(pkt(swSeq+1, append([]byte("tok"), 0))); err != nil {
		t.Fatalf("token: %v", err)
	}
	_, errPayload, _, err := readPacket(cr)
	if err != nil {
		t.Fatalf("read error packet: %v", err)
	}
	if len(errPayload) == 0 || errPayload[0] != pktERR {
		t.Fatalf("expected an ERR packet to the client, got %v", errPayload)
	}
	if err := <-proxyErr; err == nil {
		t.Fatal("expected ProxyInject to return the upstream auth error")
	}
	if err := <-upErr; err != nil {
		t.Fatalf("upstream harness: %v", err)
	}
}

// ---- terminateClient: TLS branches and read-failure paths ----

func TestTerminateClient_TLSRequestedButNotConfigured(t *testing.T) {
	engineSide, clientSide := net.Pipe()
	defer engineSide.Close()
	defer clientSide.Close()
	deadlineAll(t, engineSide, clientSide)

	errc := make(chan error, 1)
	go func() {
		cr := bufio.NewReader(clientSide)
		if _, _, _, err := readPacket(cr); err != nil { // greeting
			errc <- err
			return
		}
		var payload [4]byte
		binary.LittleEndian.PutUint32(payload[:], capClientSSL)
		_, err := clientSide.Write(pkt(1, payload[:]))
		errc <- err
	}()

	engine := New()
	_, _, _, _, err := engine.terminateClient(engineSide)
	if err == nil || !strings.Contains(err.Error(), "no client cert is configured") {
		t.Fatalf("got %v", err)
	}
	if err := <-errc; err != nil {
		t.Fatalf("client harness: %v", err)
	}
}

func TestTerminateClient_ClientTLSHandshakeFailure(t *testing.T) {
	engineSide, clientSide := net.Pipe()
	defer engineSide.Close()
	defer clientSide.Close()
	deadlineAll(t, engineSide, clientSide)

	errc := make(chan error, 1)
	go func() {
		cr := bufio.NewReader(clientSide)
		if _, _, _, err := readPacket(cr); err != nil {
			errc <- err
			return
		}
		var payload [4]byte
		binary.LittleEndian.PutUint32(payload[:], capClientSSL)
		if _, err := clientSide.Write(pkt(1, payload[:])); err != nil {
			errc <- err
			return
		}
		// Send garbage instead of a real TLS ClientHello so the server-side handshake fails.
		_, err := clientSide.Write([]byte("not-a-tls-handshake-record"))
		errc <- err
	}()

	engine := NewWithClientTLS(testServerTLS(t))
	_, _, _, _, err := engine.terminateClient(engineSide)
	if err == nil || !strings.Contains(err.Error(), "client TLS handshake failed") {
		t.Fatalf("got %v", err)
	}
	<-errc
}

func TestTerminateClient_TokenReadFailure(t *testing.T) {
	engineSide, clientSide := net.Pipe()
	defer engineSide.Close()
	deadlineAll(t, engineSide, clientSide)

	go func() {
		cr := bufio.NewReader(clientSide)
		_, _, _, _ = readPacket(cr) // greeting
		_, _ = clientSide.Write(pkt(1, clientHandshakeResp(false)))
		_, _, _, _ = readPacket(cr) // auth switch
		_ = clientSide.Close()      // disconnect before sending the token
	}()

	engine := New()
	_, _, _, _, err := engine.terminateClient(engineSide)
	if err == nil {
		t.Fatal("expected an error when the client disconnects before sending the token")
	}
}

// ---- tlsUnavailableReason: exercise every branch directly ----

func TestTlsUnavailableReason_AllBranches(t *testing.T) {
	greetingSSL := buildGreeting(capClientSSL | capClientProtocol41)
	greetingNoSSL := buildGreeting(capClientProtocol41)

	cases := []struct {
		name     string
		greeting []byte
		caps     uint32
		payload  []byte
		want     string
	}{
		{"no server ssl support", greetingNoSSL, capClientProtocol41, make([]byte, 40), "does not advertise CLIENT_SSL"},
		{"client not protocol41", greetingSSL, 0, make([]byte, 40), "not using PROTOCOL_41"},
		{"handshake too short", greetingSSL, capClientProtocol41, make([]byte, 10), "too short to derive an SSL request"},
		{"fallback default", greetingSSL, capClientProtocol41, make([]byte, sslRequestLen), "TLS is unavailable"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got := tlsUnavailableReason(c.greeting, c.caps, c.payload)
			if !strings.Contains(got, c.want) {
				t.Fatalf("got %q, want containing %q", got, c.want)
			}
		})
	}
}

// ---- Proxy: upstream TLS "prefer" mode falls back to plaintext when the server lacks SSL ----

func TestProxy_UpstreamTLSPreferFallsBackToPlaintext(t *testing.T) {
	clientConn, engineClient := net.Pipe()
	engineUpstream, upstreamConn := net.Pipe()
	defer clientConn.Close()
	defer engineUpstream.Close()
	deadlineAll(t, clientConn, engineClient, engineUpstream, upstreamConn)

	engine := New().WithUpstreamTLS(&tls.Config{InsecureSkipVerify: true}, false) //nolint:gosec // test
	proxyErr := make(chan error, 1)
	go func() {
		proxyErr <- engine.Proxy(context.Background(), engineClient, engineUpstream, mask.Noop{}, wire.NoopRecorder{})
	}()

	go func() { _, _ = upstreamConn.Write(pkt(0, buildGreeting(capClientProtocol41))) }() // no SSL advertised

	cr := bufio.NewReader(clientConn)
	if _, _, _, err := readPacket(cr); err != nil {
		t.Fatalf("greeting: %v", err)
	}
	resp := make([]byte, 40)
	binary.LittleEndian.PutUint32(resp[0:4], capClientProtocol41)
	if _, err := clientConn.Write(pkt(1, resp)); err != nil {
		t.Fatalf("handshake response: %v", err)
	}

	ur := bufio.NewReader(upstreamConn)
	useq, upayload, _, err := readPacket(ur)
	if err != nil {
		t.Fatalf("upstream read: %v", err)
	}
	if useq != 1 || !bytes.Equal(upayload, resp) {
		t.Fatal("expected the handshake response forwarded verbatim in the plaintext fallback")
	}
	if _, err := upstreamConn.Write(pkt(2, okPacket())); err != nil {
		t.Fatalf("upstream ok: %v", err)
	}
	okSeq, okP, _, err := readPacket(cr)
	if err != nil {
		t.Fatalf("client read ok: %v", err)
	}
	if okSeq != 2 || len(okP) == 0 || okP[0] != pktOK {
		t.Fatalf("unexpected ok seq/payload: seq=%d payload=%v", okSeq, okP)
	}
	_ = clientConn.Close()
	<-proxyErr
}

// ---- Proxy: nil masker/recorder defaults must not panic ----

func TestProxy_NilMaskerAndRecorderDefaultSafely(t *testing.T) {
	clientConn, engineClient := net.Pipe()
	engineUpstream, upstreamConn := net.Pipe()
	defer clientConn.Close()
	defer engineUpstream.Close()
	deadlineAll(t, clientConn, engineClient, engineUpstream, upstreamConn)

	engine := New()
	proxyErr := make(chan error, 1)
	go func() {
		proxyErr <- engine.Proxy(context.Background(), engineClient, engineUpstream, nil, nil)
	}()

	go func() { _, _ = upstreamConn.Write(pkt(0, buildGreeting(capClientProtocol41))) }()

	cr := bufio.NewReader(clientConn)
	if _, _, _, err := readPacket(cr); err != nil {
		t.Fatalf("greeting: %v", err)
	}
	_ = clientConn.Close()
	select {
	case <-proxyErr:
	case <-time.After(5 * time.Second):
		t.Fatal("Proxy did not return")
	}
}

// ---- clientToServer: write failure propagation ----

func TestClientToServer_WritePacketFailurePropagates(t *testing.T) {
	s := &state{queries: make(chan struct{}, 1)}
	in := pkt(0, []byte{comQuery})
	cb := bufio.NewReader(bytes.NewReader(in))
	err := s.clientToServer(cb, &limitWriter{n: 0}, wire.NoopRecorder{})
	if err == nil {
		t.Fatal("expected the write failure to propagate")
	}
}

// ---- serverToClient: offset-phase (upstream-TLS connection phase) read/write failure branches ----

func TestServerToClient_OffsetPhaseReadFailure(t *testing.T) {
	s := &state{queries: make(chan struct{}, 1)}
	s.offset.Store(1)
	sb := bufio.NewReader(bytes.NewReader(nil)) // immediate EOF
	var out bytes.Buffer
	err := s.serverToClient(context.Background(), sb, &out, mask.Noop{}, wire.NoopRecorder{})
	if err == nil {
		t.Fatal("expected the offset-phase read failure to propagate")
	}
}

func TestServerToClient_OffsetPhaseWriteFailure(t *testing.T) {
	s := &state{queries: make(chan struct{}, 1)}
	s.offset.Store(1)
	stream := bytes.NewReader(pkt(1, []byte{pktOK}))
	sb := bufio.NewReader(stream)
	err := s.serverToClient(context.Background(), sb, &limitWriter{n: 0}, mask.Noop{}, wire.NoopRecorder{})
	if err == nil {
		t.Fatal("expected the offset-phase write failure to propagate")
	}
}

// ---- readLenEncInt: truncated 8-byte and invalid-prefix branches not covered by the existing table ----

func TestReadLenEncInt_AdditionalBranches(t *testing.T) {
	if _, _, ok := readLenEncInt([]byte{0xFE, 1, 2, 3}, 0); ok {
		t.Fatal("expected a truncated 8-byte lenenc int to fail")
	}
	if _, _, ok := readLenEncInt([]byte{0xFF}, 0); ok {
		t.Fatal("expected 0xFF (not a valid length prefix here) to fail")
	}
	if _, _, ok := readLenEncInt(nil, 0); ok {
		t.Fatal("expected an out-of-range offset to fail")
	}
}

// ---- maskTextRow: truncated field value, invalid lenenc prefix, and wrong masker output count ----

func TestMaskTextRow_TruncatedFieldValue(t *testing.T) {
	cols := []mask.Column{{Name: "email", Text: true, FreeText: true}}
	row := appendLenEncInt(nil, 100) // claims 100 bytes, none follow
	row = append(row, "short"...)
	_, _, ok, err := maskTextRow(context.Background(), row, cols, mask.Noop{})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if ok {
		t.Fatal("expected ok=false for a truncated field value")
	}
}

func TestMaskTextRow_InvalidLenEncPrefix(t *testing.T) {
	cols := []mask.Column{{Name: "email", Text: true, FreeText: true}}
	row := []byte{0xFF} // invalid lenenc prefix (not the NULL marker 0xFB)
	_, _, ok, err := maskTextRow(context.Background(), row, cols, mask.Noop{})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if ok {
		t.Fatal("expected ok=false for an invalid lenenc length prefix")
	}
}

type wrongCountMasker struct{}

func (wrongCountMasker) MaskRow(_ context.Context, _ []mask.Column, row [][]byte) ([][]byte, error) {
	return row[:len(row)-1], nil
}

func TestMaskTextRow_MaskerReturnsWrongFieldCount(t *testing.T) {
	cols := []mask.Column{
		{Name: "id", Text: true, FreeText: true},
		{Name: "email", Text: true, FreeText: true},
	}
	row := textRow("1", "a@b.com")
	_, _, ok, err := maskTextRow(context.Background(), row, cols, wrongCountMasker{})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if ok {
		t.Fatal("expected ok=false when the masker changes the field count")
	}
}
