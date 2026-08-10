package postgres

import (
	"bufio"
	"bytes"
	"context"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/curlix-io/skybridge/internal/mask"
	"github.com/curlix-io/skybridge/internal/wire"
)

// limitWriter succeeds for the first n bytes written (across all calls) then fails — used to force a
// write failure partway through a multi-write sequence without a real broken connection.
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

// ---- authenticateUpstream: additional error branches ----

func TestAuthenticateUpstream_UnexpectedNonAuthMessage(t *testing.T) {
	client, server := net.Pipe()
	defer client.Close()
	defer server.Close()
	deadline(t, client, server)

	errc := make(chan error, 1)
	go func() {
		br := bufio.NewReader(client)
		errc <- authenticateUpstream(client, br, wire.UpstreamCredential{Username: "u", Password: "p"}, "db")
	}()

	srv := bufio.NewReader(server)
	_ = readStartupOnServer(t, srv)
	// Send a CommandComplete instead of an Authentication/ErrorResponse message.
	writeMsg(t, server, 'C', []byte("SELECT 1\x00"))

	err := <-errc
	if err == nil || !strings.Contains(err.Error(), "expected Authentication message") {
		t.Fatalf("got %v", err)
	}
}

func TestAuthenticateUpstream_TruncatedAuthPayload(t *testing.T) {
	client, server := net.Pipe()
	defer client.Close()
	defer server.Close()
	deadline(t, client, server)

	errc := make(chan error, 1)
	go func() {
		br := bufio.NewReader(client)
		errc <- authenticateUpstream(client, br, wire.UpstreamCredential{Username: "u", Password: "p"}, "db")
	}()

	srv := bufio.NewReader(server)
	_ = readStartupOnServer(t, srv)
	writeMsg(t, server, msgAuthentication, []byte{0, 1}) // < 4 bytes

	err := <-errc
	if !errors.Is(err, errProtocol) {
		t.Fatalf("got %v, want errProtocol", err)
	}
}

func TestAuthenticateUpstream_MD5TruncatedSalt(t *testing.T) {
	client, server := net.Pipe()
	defer client.Close()
	defer server.Close()
	deadline(t, client, server)

	errc := make(chan error, 1)
	go func() {
		br := bufio.NewReader(client)
		errc <- authenticateUpstream(client, br, wire.UpstreamCredential{Username: "u", Password: "p"}, "db")
	}()

	srv := bufio.NewReader(server)
	_ = readStartupOnServer(t, srv)
	payload := make([]byte, 4) // authMD5Password code but no 4-byte salt following
	binary.BigEndian.PutUint32(payload, authMD5Password)
	writeMsg(t, server, msgAuthentication, payload)

	err := <-errc
	if !errors.Is(err, errProtocol) {
		t.Fatalf("got %v, want errProtocol", err)
	}
}

func TestAuthenticateUpstream_UnsupportedAuthMethod(t *testing.T) {
	client, server := net.Pipe()
	defer client.Close()
	defer server.Close()
	deadline(t, client, server)

	errc := make(chan error, 1)
	go func() {
		br := bufio.NewReader(client)
		errc <- authenticateUpstream(client, br, wire.UpstreamCredential{Username: "u", Password: "p"}, "db")
	}()

	srv := bufio.NewReader(server)
	_ = readStartupOnServer(t, srv)
	writeAuth(t, server, 9999, nil) // no such auth method

	err := <-errc
	if err == nil || !strings.Contains(err.Error(), "unsupported authentication method") {
		t.Fatalf("got %v", err)
	}
}

func TestAuthenticateUpstream_StartupMessageWriteFailure(t *testing.T) {
	br := bufio.NewReader(bytes.NewReader(nil))
	err := authenticateUpstream(&limitWriter{n: 0}, br, wire.UpstreamCredential{Username: "u", Password: "p"}, "db")
	if err == nil {
		t.Fatal("expected the startup message write failure to propagate")
	}
}

// ---- scramClientExchange: mechanism/nonce/salt/iteration/signature error branches ----

func TestScramClientExchange_MechanismNotOffered(t *testing.T) {
	err := scramClientExchange(&bytes.Buffer{}, bufio.NewReader(bytes.NewReader(nil)), []byte("SCRAM-SHA-1\x00"), "pw")
	if err == nil || !strings.Contains(err.Error(), "did not offer") {
		t.Fatalf("got %v", err)
	}
}

func TestScramClientExchange_InitialResponseWriteFailure(t *testing.T) {
	err := scramClientExchange(&limitWriter{n: 0}, bufio.NewReader(bytes.NewReader(nil)), []byte(scramSHA256+"\x00"), "pw")
	if err == nil {
		t.Fatal("expected the SASLInitialResponse write failure to propagate")
	}
}

func TestScramClientExchange_ServerErrorInsteadOfContinue(t *testing.T) {
	var out bytes.Buffer
	var in bytes.Buffer
	errPayload := []byte{'M'}
	errPayload = append(errPayload, "bad mechanism"...)
	errPayload = append(errPayload, 0, 0)
	writeMsg(t, &in, msgErrorResponse, errPayload)

	err := scramClientExchange(&out, bufio.NewReader(&in), []byte(scramSHA256+"\x00"), "pw")
	if err == nil || !strings.Contains(err.Error(), "bad mechanism") {
		t.Fatalf("got %v", err)
	}
}

func TestScramClientExchange_UnexpectedContinueType(t *testing.T) {
	var out bytes.Buffer
	var in bytes.Buffer
	writeMsg(t, &in, 'C', []byte("not-auth"))

	err := scramClientExchange(&out, bufio.NewReader(&in), []byte(scramSHA256+"\x00"), "pw")
	if err == nil || !strings.Contains(err.Error(), "expected AuthenticationSASLContinue") {
		t.Fatalf("got %v", err)
	}
}

func TestScramClientExchange_MalformedServerFirst(t *testing.T) {
	var out bytes.Buffer
	var in bytes.Buffer
	authPayload := make([]byte, 4)
	binary.BigEndian.PutUint32(authPayload, authSASLContinue)
	authPayload = append(authPayload, "garbage-no-attrs"...)
	writeMsg(t, &in, msgAuthentication, authPayload)

	err := scramClientExchange(&out, bufio.NewReader(&in), []byte(scramSHA256+"\x00"), "pw")
	if err == nil || !strings.Contains(err.Error(), "malformed SCRAM server-first") {
		t.Fatalf("got %v", err)
	}
}

func TestScramClientExchange_NonceMismatch(t *testing.T) {
	var out bytes.Buffer
	var in bytes.Buffer
	serverFirst := "r=totally-different-nonce,s=" + base64.StdEncoding.EncodeToString([]byte("salt")) + ",i=4096"
	authPayload := make([]byte, 4)
	binary.BigEndian.PutUint32(authPayload, authSASLContinue)
	authPayload = append(authPayload, serverFirst...)
	writeMsg(t, &in, msgAuthentication, authPayload)

	err := scramClientExchange(&out, bufio.NewReader(&in), []byte(scramSHA256+"\x00"), "pw")
	if err == nil || !strings.Contains(err.Error(), "does not extend client nonce") {
		t.Fatalf("got %v", err)
	}
}

func TestScramClientExchange_BadSaltBase64(t *testing.T) {
	// scramClientExchange generates a fresh random client nonce on every call, so drive it over a
	// net.Pipe with a harness that reads the real SASLInitialResponse, extracts that call's nonce,
	// and replies with a server-first extending it but carrying an invalid salt.
	client, server := net.Pipe()
	defer client.Close()
	defer server.Close()
	deadline(t, client, server)

	errc := make(chan error, 1)
	go func() {
		errc <- scramClientExchange(client, bufio.NewReader(client), []byte(scramSHA256+"\x00"), "pw")
	}()

	srv := bufio.NewReader(server)
	clientNonce := scramClientNonce(t, srv)
	serverFirst := "r=" + clientNonce + "ext,s=not-valid-base64!!,i=4096"
	writeAuthRaw(server, authSASLContinue, []byte(serverFirst))

	err := <-errc
	if err == nil || !strings.Contains(err.Error(), "bad SCRAM salt") {
		t.Fatalf("got %v", err)
	}
}

// scramClientNonce reads a real SASLInitialResponse off srv (already offered SCRAM-SHA-256) and
// returns the client nonce scramClientExchange generated for this call, so a test can build a
// server-first message that correctly "extends" it.
func scramClientNonce(t *testing.T, srv *bufio.Reader) string {
	t.Helper()
	typ, payload, err := readBackendMessage(srv)
	if err != nil || typ != msgPassword {
		t.Fatalf("expected SASLInitialResponse: typ=%q err=%v", string(rune(typ)), err)
	}
	zero := indexZero(payload, 0)
	rest := payload[zero+1:]
	respLen := int(binary.BigEndian.Uint32(rest[0:4]))
	clientFirst := string(rest[4 : 4+respLen])
	return parseSCRAMAttrs(strings.TrimPrefix(clientFirst, "n,,"))["r"]
}

func TestScramClientExchange_BadIterationCount(t *testing.T) {
	client, server := net.Pipe()
	defer client.Close()
	defer server.Close()
	deadline(t, client, server)

	errc := make(chan error, 1)
	go func() {
		errc <- scramClientExchange(client, bufio.NewReader(client), []byte(scramSHA256+"\x00"), "pw")
	}()

	srv := bufio.NewReader(server)
	clientNonce := scramClientNonce(t, srv)
	serverFirst := "r=" + clientNonce + "ext,s=" + base64.StdEncoding.EncodeToString([]byte("salt")) + ",i=notanumber"
	writeAuthRaw(server, authSASLContinue, []byte(serverFirst))

	err := <-errc
	if err == nil || !strings.Contains(err.Error(), "bad SCRAM iteration count") {
		t.Fatalf("got %v", err)
	}
}

func TestScramClientExchange_ZeroIterationCountRejected(t *testing.T) {
	client, server := net.Pipe()
	defer client.Close()
	defer server.Close()
	deadline(t, client, server)

	errc := make(chan error, 1)
	go func() {
		errc <- scramClientExchange(client, bufio.NewReader(client), []byte(scramSHA256+"\x00"), "pw")
	}()

	srv := bufio.NewReader(server)
	clientNonce := scramClientNonce(t, srv)
	serverFirst := "r=" + clientNonce + "ext,s=" + base64.StdEncoding.EncodeToString([]byte("salt")) + ",i=0"
	writeAuthRaw(server, authSASLContinue, []byte(serverFirst))

	err := <-errc
	if err == nil || !strings.Contains(err.Error(), "bad SCRAM iteration count") {
		t.Fatalf("got %v", err)
	}
}

func TestScramClientExchange_ClientFinalWriteFailure(t *testing.T) {
	// Use the real SCRAM server harness for a valid server-first, but fail the client-final write.
	client, server := net.Pipe()
	defer client.Close()
	defer server.Close()
	deadline(t, client, server)

	errc := make(chan error, 1)
	go func() {
		br := bufio.NewReader(client)
		errc <- authenticateUpstream(client, br, wire.UpstreamCredential{Username: "svc", Password: "pw"}, "db")
	}()
	// Drive the server side up through server-first, then close the pipe so the client-final write fails.
	srv := bufio.NewReader(server)
	var hdr [8]byte
	_, _ = readFull(srv, hdr[:])
	body := make([]byte, int(binary.BigEndian.Uint32(hdr[0:4]))-8)
	_, _ = readFull(srv, body)
	writeAuthRaw(server, authSASL, append([]byte(scramSHA256), 0))
	_, _, _ = readBackendMessage(srv) // SASLInitialResponse
	_ = server.Close()                // force the client-final write to fail

	err := <-errc
	if err == nil {
		t.Fatal("expected an error once the connection is closed before the client-final message")
	}
}

func TestScramClientExchange_ServerErrorInsteadOfFinal(t *testing.T) {
	client, server := net.Pipe()
	defer client.Close()
	defer server.Close()
	deadline(t, client, server)

	errc := make(chan error, 1)
	go func() {
		br := bufio.NewReader(client)
		errc <- authenticateUpstream(client, br, wire.UpstreamCredential{Username: "svc", Password: "pw"}, "db")
	}()

	srv := bufio.NewReader(server)
	var hdr [8]byte
	_, _ = readFull(srv, hdr[:])
	body := make([]byte, int(binary.BigEndian.Uint32(hdr[0:4]))-8)
	_, _ = readFull(srv, body)
	writeAuthRaw(server, authSASL, append([]byte(scramSHA256), 0))
	_, _, _ = readBackendMessage(srv) // SASLInitialResponse

	// An ErrorResponse in place of AuthenticationSASLContinue hits the "upstream rejected SCRAM"
	// branch directly; it doesn't require a valid nonce/server-first at all.
	errPayload := []byte{'M'}
	errPayload = append(errPayload, "scram continue rejected"...)
	errPayload = append(errPayload, 0, 0)
	writeMsg(t, server, msgErrorResponse, errPayload)

	err := <-errc
	if err == nil || !strings.Contains(err.Error(), "scram continue rejected") {
		t.Fatalf("got %v", err)
	}
}

func TestScramClientExchange_BadServerSignatureBase64(t *testing.T) {
	client, server := net.Pipe()
	defer client.Close()
	defer server.Close()
	deadline(t, client, server)

	errc := make(chan error, 1)
	go func() {
		br := bufio.NewReader(client)
		errc <- authenticateUpstream(client, br, wire.UpstreamCredential{Username: "svc", Password: "pw"}, "db")
	}()

	srv := bufio.NewReader(server)
	var hdr [8]byte
	_, _ = readFull(srv, hdr[:])
	body := make([]byte, int(binary.BigEndian.Uint32(hdr[0:4]))-8)
	_, _ = readFull(srv, body)
	writeAuthRaw(server, authSASL, append([]byte(scramSHA256), 0))

	typ, payload, err := readBackendMessage(srv)
	if err != nil || typ != msgPassword {
		t.Fatalf("expected SASLInitialResponse: typ=%q err=%v", string(rune(typ)), err)
	}
	zero := indexZero(payload, 0)
	rest := payload[zero+1:]
	respLen := int(binary.BigEndian.Uint32(rest[0:4]))
	clientFirst := string(rest[4 : 4+respLen])
	clientNonce := parseSCRAMAttrs(strings.TrimPrefix(clientFirst, "n,,"))["r"]

	salt := []byte("0123456789abcdef")
	serverFirst := "r=" + clientNonce + "serverpart,s=" + base64.StdEncoding.EncodeToString(salt) + ",i=4096"
	writeAuthRaw(server, authSASLContinue, []byte(serverFirst))

	_, _, _ = readBackendMessage(srv) // client-final (proof), ignored

	// Reply with a syntactically-valid AuthenticationSASLFinal but a garbage (non-base64) 'v' value.
	writeAuthRaw(server, authSASLFinal, []byte("v=not-valid-base64!!"))

	err = <-errc
	if err == nil || !strings.Contains(err.Error(), "bad SCRAM server signature") {
		t.Fatalf("got %v", err)
	}
}

func TestScramClientExchange_UnexpectedFinalType(t *testing.T) {
	client, server := net.Pipe()
	defer client.Close()
	defer server.Close()
	deadline(t, client, server)

	errc := make(chan error, 1)
	go func() {
		br := bufio.NewReader(client)
		errc <- authenticateUpstream(client, br, wire.UpstreamCredential{Username: "svc", Password: "pw"}, "db")
	}()

	srv := bufio.NewReader(server)
	var hdr [8]byte
	_, _ = readFull(srv, hdr[:])
	body := make([]byte, int(binary.BigEndian.Uint32(hdr[0:4]))-8)
	_, _ = readFull(srv, body)
	writeAuthRaw(server, authSASL, append([]byte(scramSHA256), 0))

	typ, payload, err := readBackendMessage(srv)
	if err != nil || typ != msgPassword {
		t.Fatalf("expected SASLInitialResponse: typ=%q err=%v", string(rune(typ)), err)
	}
	zero := indexZero(payload, 0)
	rest := payload[zero+1:]
	respLen := int(binary.BigEndian.Uint32(rest[0:4]))
	clientFirst := string(rest[4 : 4+respLen])
	clientNonce := parseSCRAMAttrs(strings.TrimPrefix(clientFirst, "n,,"))["r"]

	salt := []byte("0123456789abcdef")
	serverFirst := "r=" + clientNonce + "serverpart,s=" + base64.StdEncoding.EncodeToString(salt) + ",i=4096"
	writeAuthRaw(server, authSASLContinue, []byte(serverFirst))
	_, _, _ = readBackendMessage(srv) // client-final

	// Send a non-authentication message instead of AuthenticationSASLFinal.
	writeMsg(t, server, 'C', []byte("unexpected"))

	err = <-errc
	if err == nil || !strings.Contains(err.Error(), "expected AuthenticationSASLFinal") {
		t.Fatalf("got %v", err)
	}
}

func TestMechanismOffered_MultipleAndAbsent(t *testing.T) {
	if !mechanismOffered([]byte("SCRAM-SHA-1\x00SCRAM-SHA-256\x00"), scramSHA256) {
		t.Fatal("expected SCRAM-SHA-256 to be found among multiple offered mechanisms")
	}
	if mechanismOffered([]byte("SCRAM-SHA-1\x00"), scramSHA256) {
		t.Fatal("expected mechanismOffered=false when SCRAM-SHA-256 is absent")
	}
}

// ---- readStartupParams / requestClientPassword: additional error branches ----

func TestReadStartupParams_WrongVersion(t *testing.T) {
	var body []byte
	hdr := make([]byte, 8)
	binary.BigEndian.PutUint32(hdr[0:4], uint32(8+len(body)))
	binary.BigEndian.PutUint32(hdr[4:8], 12345) // not startupProtocolV3
	cr := bufio.NewReader(bytes.NewReader(hdr))
	if _, err := readStartupParams(cr); err == nil {
		t.Fatal("expected an error for an unsupported startup protocol version")
	}
}

func TestReadStartupParams_OversizedLength(t *testing.T) {
	hdr := make([]byte, 8)
	binary.BigEndian.PutUint32(hdr[0:4], sniffStartupCap+1)
	binary.BigEndian.PutUint32(hdr[4:8], startupProtocolV3)
	cr := bufio.NewReader(bytes.NewReader(hdr))
	if _, err := readStartupParams(cr); !errors.Is(err, errProtocol) {
		t.Fatalf("got %v, want errProtocol", err)
	}
}

func TestReadStartupParams_TruncatedBody(t *testing.T) {
	hdr := make([]byte, 8)
	binary.BigEndian.PutUint32(hdr[0:4], 20) // claims 12 bytes of body
	binary.BigEndian.PutUint32(hdr[4:8], startupProtocolV3)
	cr := bufio.NewReader(bytes.NewReader(hdr)) // no body bytes follow
	if _, err := readStartupParams(cr); err == nil {
		t.Fatal("expected an error for a truncated startup body")
	}
}

func TestRequestClientPassword_UnexpectedMessageType(t *testing.T) {
	client, server := net.Pipe()
	defer client.Close()
	defer server.Close()
	deadline(t, client, server)

	errc := make(chan error, 1)
	go func() {
		br := bufio.NewReader(client)
		_, err := requestClientPassword(client, br)
		errc <- err
	}()

	srv := bufio.NewReader(server)
	typ, _, err := readBackendMessage(srv) // AuthenticationCleartextPassword request
	if err != nil || typ != msgAuthentication {
		t.Fatalf("expected auth request, got typ=%q err=%v", string(rune(typ)), err)
	}
	writeMsg(t, server, 'Q', []byte("not-a-password-message"))

	err = <-errc
	if err == nil || !strings.Contains(err.Error(), "expected PasswordMessage") {
		t.Fatalf("got %v", err)
	}
}

func TestRequestClientPassword_WriteFailure(t *testing.T) {
	_, err := requestClientPassword(&limitWriter{n: 0}, bufio.NewReader(bytes.NewReader(nil)))
	if err == nil {
		t.Fatal("expected the AuthenticationCleartextPassword write failure to propagate")
	}
}

func TestSendClientAuthOK_WriteFailure(t *testing.T) {
	if err := sendClientAuthOK(&limitWriter{n: 0}); err == nil {
		t.Fatal("expected the write failure to propagate")
	}
}

// ---- writeStartupMessage / writePasswordMessage / writeFrontend: write-failure branches ----

func TestWriteStartupMessage_WriteFailure(t *testing.T) {
	if err := writeStartupMessage(&limitWriter{n: 0}, "u", "db"); err == nil {
		t.Fatal("expected a write failure")
	}
}

func TestWriteFrontend_HeaderAndPayloadFailures(t *testing.T) {
	if err := writeFrontend(&limitWriter{n: 0}, msgPassword, []byte("x")); err == nil {
		t.Fatal("expected a header write failure")
	}
	if err := writeFrontend(&limitWriter{n: 5}, msgPassword, []byte("xyz")); err == nil {
		t.Fatal("expected a payload write failure")
	}
}

// ---- readBackendMessage: truncated-length guard ----

func TestReadBackendMessage_LengthTooShort(t *testing.T) {
	hdr := []byte{msgAuthentication, 0, 0, 0, 2} // length=2 < 4 minimum
	if _, _, err := readBackendMessage(bufio.NewReader(bytes.NewReader(hdr))); !errors.Is(err, errProtocol) {
		t.Fatalf("got %v, want errProtocol", err)
	}
}

// ---- ProxyInject: rejection and error-return paths ----

func TestProxyInject_ResolveFailureSendsClientError(t *testing.T) {
	clientEnd, agentClient := net.Pipe()
	agentUpstream, upstreamEnd := net.Pipe()
	defer clientEnd.Close()
	defer agentUpstream.Close()
	deadline(t, clientEnd, agentClient, agentUpstream, upstreamEnd)

	resolve := func(_ context.Context, _ map[string]string, _ string) (wire.UpstreamCredential, error) {
		return wire.UpstreamCredential{}, errors.New("denied")
	}
	proxyErr := make(chan error, 1)
	go func() {
		proxyErr <- (&Engine{}).ProxyInject(context.Background(), agentClient, agentUpstream, mask.Noop{}, resolve, wire.NoopRecorder{})
	}()

	if err := writeStartupMessage(clientEnd, "alice", "appdb"); err != nil {
		t.Fatalf("client startup: %v", err)
	}
	cr := bufio.NewReader(clientEnd)
	typ, payload, err := readBackendMessage(cr)
	if err != nil || typ != msgAuthentication || binary.BigEndian.Uint32(payload[0:4]) != authCleartextPassword {
		t.Fatalf("expected cleartext password request, got typ=%q err=%v", string(rune(typ)), err)
	}
	if err := writePasswordMessage(clientEnd, "bad-token"); err != nil {
		t.Fatalf("client send token: %v", err)
	}
	typ, payload, err = readBackendMessage(cr)
	if err != nil || typ != msgErrorResponse {
		t.Fatalf("expected an ErrorResponse to the client, got typ=%q err=%v", string(rune(typ)), err)
	}
	if !strings.Contains(parseErrorResponse(payload), "access denied") {
		t.Fatalf("unexpected error message: %s", parseErrorResponse(payload))
	}
	if err := <-proxyErr; err == nil {
		t.Fatal("expected ProxyInject to return the resolver's error")
	}
}

func TestProxyInject_UpstreamAuthFailureSendsClientError(t *testing.T) {
	clientEnd, agentClient := net.Pipe()
	agentUpstream, upstreamEnd := net.Pipe()
	defer clientEnd.Close()
	defer agentUpstream.Close()
	deadline(t, clientEnd, agentClient, agentUpstream, upstreamEnd)

	resolve := func(_ context.Context, _ map[string]string, _ string) (wire.UpstreamCredential, error) {
		return wire.UpstreamCredential{Username: "svc", Password: "irrelevant"}, nil
	}
	proxyErr := make(chan error, 1)
	go func() {
		proxyErr <- (&Engine{}).ProxyInject(context.Background(), agentClient, agentUpstream, mask.Noop{}, resolve, wire.NoopRecorder{})
	}()

	upErr := make(chan error, 1)
	go func() {
		srv := bufio.NewReader(upstreamEnd)
		var hdr [8]byte
		if _, err := readFull(srv, hdr[:]); err != nil {
			upErr <- err
			return
		}
		body := make([]byte, int(binary.BigEndian.Uint32(hdr[0:4]))-8)
		if _, err := readFull(srv, body); err != nil {
			upErr <- err
			return
		}
		errPayload := []byte{'M'}
		errPayload = append(errPayload, "authentication failed"...)
		errPayload = append(errPayload, 0, 0)
		upErr <- writeMsgRaw(upstreamEnd, msgErrorResponse, errPayload)
	}()

	if err := writeStartupMessage(clientEnd, "alice", "appdb"); err != nil {
		t.Fatalf("client startup: %v", err)
	}
	cr := bufio.NewReader(clientEnd)
	_, _, err := readBackendMessage(cr) // cleartext password request
	if err != nil {
		t.Fatalf("read auth request: %v", err)
	}
	if err := writePasswordMessage(clientEnd, "good-token"); err != nil {
		t.Fatalf("client send token: %v", err)
	}
	typ, payload, err := readBackendMessage(cr)
	if err != nil || typ != msgErrorResponse {
		t.Fatalf("expected an ErrorResponse to the client, got typ=%q err=%v", string(rune(typ)), err)
	}
	if !strings.Contains(parseErrorResponse(payload), "upstream authentication failed") {
		t.Fatalf("unexpected error message: %s", parseErrorResponse(payload))
	}
	if err := <-proxyErr; err == nil {
		t.Fatal("expected ProxyInject to return the upstream auth error")
	}
	if err := <-upErr; err != nil {
		t.Fatalf("upstream harness: %v", err)
	}
}

func TestProxyInject_NilResolverErrors(t *testing.T) {
	err := (&Engine{}).ProxyInject(context.Background(), nil, nil, nil, nil, nil)
	if err == nil || !strings.Contains(err.Error(), "requires a resolver") {
		t.Fatalf("got %v", err)
	}
}

func TestProxyInject_StartupReadFailure(t *testing.T) {
	clientEnd, agentClient := net.Pipe()
	deadline(t, clientEnd, agentClient)
	_ = clientEnd.Close() // disconnect before sending anything

	resolve := func(_ context.Context, _ map[string]string, _ string) (wire.UpstreamCredential, error) {
		return wire.UpstreamCredential{}, nil
	}
	err := (&Engine{}).ProxyInject(context.Background(), agentClient, nil, nil, resolve, nil)
	if err == nil {
		t.Fatal("expected an error when the client disconnects before the StartupMessage")
	}
}

// ---- Proxy: nil masker/recorder don't panic; error propagation from client read failure ----

func TestProxy_NilMaskerAndRecorderDefaultSafely(t *testing.T) {
	clientEnd, agentClient := net.Pipe()
	agentUpstream, upstreamEnd := net.Pipe()
	defer clientEnd.Close()
	defer agentUpstream.Close()
	deadline(t, clientEnd, agentClient, agentUpstream, upstreamEnd)

	engine := New()
	proxyErr := make(chan error, 1)
	go func() {
		proxyErr <- engine.Proxy(context.Background(), agentClient, agentUpstream, nil, nil)
	}()

	startup := startupMessage(map[string]string{"user": "alice"})
	if _, err := clientEnd.Write(startup); err != nil {
		t.Fatalf("client write startup: %v", err)
	}
	got := make([]byte, len(startup))
	if _, err := readFull(bufio.NewReader(upstreamEnd), got); err != nil {
		t.Fatalf("upstream read: %v", err)
	}
	if !bytes.Equal(got, startup) {
		t.Fatal("expected the startup message forwarded verbatim")
	}
	_ = clientEnd.Close()
	_ = upstreamEnd.Close()
	select {
	case <-proxyErr:
	case <-time.After(5 * time.Second):
		t.Fatal("Proxy did not return")
	}
}

// ---- pipeBackendReader: write failures propagate ----

func TestPipeBackendReader_WriteFailurePropagates(t *testing.T) {
	server := new(bytes.Buffer)
	writeMsg(t, server, 'C', []byte("SELECT 1"))
	err := pipeBackend(context.Background(), bytes.NewReader(server.Bytes()), &limitWriter{n: 0}, mask.Noop{}, wire.NoopRecorder{}, nil)
	if err == nil {
		t.Fatal("expected the client write failure to propagate")
	}
}

// ---- negotiateStartup: write failures on the SSL negotiation reply ----

func TestNegotiateStartup_DeclineWriteFailure(t *testing.T) {
	// Use a net.Pipe and close the far end before the reply so the 'N' write fails.
	clientEnd, serverEnd := net.Pipe()
	deadline(t, clientEnd, serverEnd)

	go func() {
		var hdr [8]byte
		binary.BigEndian.PutUint32(hdr[0:4], 8)
		binary.BigEndian.PutUint32(hdr[4:8], sslRequestCode)
		_, _ = clientEnd.Write(hdr[:])
		_ = clientEnd.Close() // closes before the server can write back 'N'
	}()

	_, _, err := negotiateStartup(serverEnd, nil)
	if err == nil {
		t.Fatal("expected an error when the decline write fails")
	}
	_ = serverEnd.Close()
}

// ---- catalog.go: query/drainToReady/runSimpleQuery error branches ----

func TestDrainToReady_ErrorResponseSurfaces(t *testing.T) {
	var buf bytes.Buffer
	errPayload := []byte{'M'}
	errPayload = append(errPayload, "setup failed"...)
	errPayload = append(errPayload, 0, 0)
	writeMsg(t, &buf, msgErrorResponse, errPayload)

	err := drainToReady(bufio.NewReader(&buf))
	if err == nil || !strings.Contains(err.Error(), "setup failed") {
		t.Fatalf("got %v", err)
	}
}

func TestDrainToReady_ReadFailure(t *testing.T) {
	err := drainToReady(bufio.NewReader(bytes.NewReader(nil)))
	if err == nil {
		t.Fatal("expected an error on immediate EOF")
	}
}

func TestRunSimpleQuery_WriteFailure(t *testing.T) {
	_, err := runSimpleQuery(&failConn{limitWriter: limitWriter{n: 0}}, bufio.NewReader(bytes.NewReader(nil)), "SELECT 1")
	if err == nil {
		t.Fatal("expected the Query message write failure to propagate")
	}
}

func TestRunSimpleQuery_ErrorResponse(t *testing.T) {
	var buf bytes.Buffer
	errPayload := []byte{'M'}
	errPayload = append(errPayload, "query failed"...)
	errPayload = append(errPayload, 0, 0)
	writeMsg(t, &buf, msgErrorResponse, errPayload)

	_, err := runSimpleQuery(&failConn{limitWriter: limitWriter{n: 1 << 20}}, bufio.NewReader(&buf), "SELECT 1")
	if err == nil || !strings.Contains(err.Error(), "query failed") {
		t.Fatalf("got %v", err)
	}
}

// failConn wraps limitWriter to satisfy net.Conn for runSimpleQuery's signature (only Write is used).
type failConn struct {
	limitWriter
	net.Conn
}

func (f *failConn) Write(p []byte) (int, error) { return f.limitWriter.Write(p) }

func TestSimpleRowDescriptionNames_TruncatedTrailerStops(t *testing.T) {
	var buf bytes.Buffer
	var u16 [2]byte
	binary.BigEndian.PutUint16(u16[:], 2) // claims 2 columns
	buf.Write(u16[:])
	buf.WriteString("relname")
	buf.WriteByte(0)
	buf.Write(make([]byte, 10)) // short of the 18-byte fixed trailer

	// The column's name is captured before its fixed trailer is checked, so a truncated second
	// column still leaves the first, fully-parsed name in the result — only the truncated column
	// itself is dropped.
	names := simpleRowDescriptionNames(buf.Bytes())
	if len(names) != 1 || names[0] != "relname" {
		t.Fatalf("expected exactly the one fully-named column, got %v", names)
	}
}

func TestSimpleRowDescriptionNames_MissingTerminator(t *testing.T) {
	var buf bytes.Buffer
	var u16 [2]byte
	binary.BigEndian.PutUint16(u16[:], 1)
	buf.Write(u16[:])
	buf.WriteString("unterminated")

	if names := simpleRowDescriptionNames(buf.Bytes()); len(names) != 0 {
		t.Fatalf("expected no columns, got %v", names)
	}
}

func TestSimpleRowDescriptionNames_EmptyPayload(t *testing.T) {
	if names := simpleRowDescriptionNames([]byte{0}); names != nil {
		t.Fatalf("expected nil, got %v", names)
	}
}

func TestParseCatalogDataRow_TruncatedLengthHeader(t *testing.T) {
	var buf bytes.Buffer
	var u16 [2]byte
	binary.BigEndian.PutUint16(u16[:], 1)
	buf.Write(u16[:])
	buf.Write([]byte{0, 0}) // only 2 of 4 length bytes

	info := parseCatalogDataRow(buf.Bytes(), []string{"relname"})
	if info.table != "" || info.schema != "" {
		t.Fatalf("expected empty tableInfo for a truncated length header, got %+v", info)
	}
}

func TestParseCatalogDataRow_TruncatedValue(t *testing.T) {
	var buf bytes.Buffer
	var u16 [2]byte
	binary.BigEndian.PutUint16(u16[:], 1)
	buf.Write(u16[:])
	var flen [4]byte
	binary.BigEndian.PutUint32(flen[:], 100)
	buf.Write(flen[:])
	buf.WriteString("short")

	info := parseCatalogDataRow(buf.Bytes(), []string{"relname"})
	if info.table != "" {
		t.Fatalf("expected empty tableInfo for a truncated value, got %+v", info)
	}
}

func TestParseCatalogDataRow_EmptyPayload(t *testing.T) {
	if info := parseCatalogDataRow([]byte{0}, []string{"relname"}); info.table != "" || info.schema != "" {
		t.Fatalf("expected empty tableInfo, got %+v", info)
	}
}

func TestParseCatalogDataRow_NullValueSkipped(t *testing.T) {
	var buf bytes.Buffer
	var u16 [2]byte
	binary.BigEndian.PutUint16(u16[:], 2)
	buf.Write(u16[:])
	var neg [4]byte
	binary.BigEndian.PutUint32(neg[:], 0xFFFFFFFF) // NULL
	buf.Write(neg[:])
	var flen [4]byte
	binary.BigEndian.PutUint32(flen[:], uint32(len("shop")))
	buf.Write(flen[:])
	buf.WriteString("shop")

	info := parseCatalogDataRow(buf.Bytes(), []string{"relname", "relnamespace"})
	if info.table != "" {
		t.Fatalf("expected NULL relname to leave table empty, got %q", info.table)
	}
	if info.schema != "shop" {
		t.Fatalf("expected schema=shop, got %q", info.schema)
	}
}

// ---- CatalogResolver.query: dial failure drops the connection and returns unresolved (already
// covered indirectly by TestCatalogResolver_UnreachableServerUnresolved); add a case for a query
// error on an already-open connection redialing on the next call. ----

func TestCatalogResolver_QueryErrorDropsConnectionForRedial(t *testing.T) {
	// A server that completes auth but then always returns ErrorResponse for the query.
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer ln.Close()
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				br := bufio.NewReader(c)
				var hdr [8]byte
				if _, err := readFull(br, hdr[:]); err != nil {
					return
				}
				body := make([]byte, int(binary.BigEndian.Uint32(hdr[0:4]))-8)
				if _, err := readFull(br, body); err != nil {
					return
				}
				if err := writeAuthOK(c); err != nil {
					return
				}
				if err := writeMsgRaw(c, 'Z', []byte{'I'}); err != nil {
					return
				}
				for {
					typ, _, err := readBackendMessage(br)
					if err != nil {
						return
					}
					if typ != msgQuery {
						continue
					}
					errPayload := []byte{'M'}
					errPayload = append(errPayload, "relation does not exist"...)
					errPayload = append(errPayload, 0, 0)
					if err := writeMsgRaw(c, msgErrorResponse, errPayload); err != nil {
						return
					}
				}
			}(conn)
		}
	}()

	host, port, splitErr := net.SplitHostPort(ln.Addr().String())
	if splitErr != nil {
		t.Fatalf("split addr: %v", splitErr)
	}
	r := NewCatalogResolver(CatalogCredential{Host: host, Port: port, User: "u", Password: "p"})
	_, _, ok := r.Resolve(context.Background(), "shop", 42)
	if ok {
		t.Fatal("expected a query error to resolve as unresolved")
	}
	// The connection should have been dropped; a second call should redial (and fail the same way)
	// rather than reusing a desynced connection. We can't observe the redial directly, but at minimum
	// this must not panic or hang.
	_, _, ok = r.Resolve(context.Background(), "shop", 42)
	if ok {
		t.Fatal("expected the second lookup to also resolve as unresolved")
	}
}
