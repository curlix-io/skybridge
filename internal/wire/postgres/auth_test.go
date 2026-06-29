package postgres

import (
	"bufio"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"io"
	"net"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/curlix-io/skybridge/internal/wire"
)

func TestPBKDF2SHA256Vectors(t *testing.T) {
	// Well-known PBKDF2-HMAC-SHA256 test vector (P="password", S="salt", c=1, dkLen=32).
	got := hex.EncodeToString(pbkdf2SHA256([]byte("password"), []byte("salt"), 1, 32))
	want := "120fb6cffcf8b32c43e7225256c4f837a86548c92ccc35480805987cb70be17b"
	if got != want {
		t.Fatalf("pbkdf2 c=1: got %s want %s", got, want)
	}
	got2 := hex.EncodeToString(pbkdf2SHA256([]byte("password"), []byte("salt"), 2, 32))
	want2 := "ae4d0c95af6b46d32d0adff928f06dd02a303f8ef3c251dfd6e2d85a95474c43"
	if got2 != want2 {
		t.Fatalf("pbkdf2 c=2: got %s want %s", got2, want2)
	}
}

func TestMD5Password(t *testing.T) {
	// Reference: "md5" + md5(md5(password+user) + salt), hex lowercase.
	salt := []byte{0x01, 0x02, 0x03, 0x04}
	got := md5Password("alice", "secret", salt)
	inner := md5Hex([]byte("secret" + "alice"))
	want := "md5" + md5Hex(append([]byte(inner), salt...))
	if got != want {
		t.Fatalf("md5Password: got %s want %s", got, want)
	}
	if !strings.HasPrefix(got, "md5") || len(got) != 35 {
		t.Fatalf("md5Password shape wrong: %q", got)
	}
}

func TestAuthenticateUpstreamTrust(t *testing.T) {
	// Backend immediately answers AuthenticationOk (trust / cert auth): no password exchange.
	client, server := net.Pipe()
	defer client.Close()
	defer server.Close()
	deadline(t, client, server)

	errc := make(chan error, 1)
	go func() {
		br := bufio.NewReader(client)
		errc <- authenticateUpstream(client, br, wire.UpstreamCredential{Username: "u", Password: "p"}, "appdb")
	}()

	srv := bufio.NewReader(server)
	params := readStartupOnServer(t, srv)
	if params["user"] != "u" || params["database"] != "appdb" {
		t.Fatalf("startup params = %v", params)
	}
	writeAuth(t, server, authOK, nil)

	if err := <-errc; err != nil {
		t.Fatalf("authenticateUpstream(trust): %v", err)
	}
}

func TestAuthenticateUpstreamCleartext(t *testing.T) {
	client, server := net.Pipe()
	defer client.Close()
	defer server.Close()
	deadline(t, client, server)

	errc := make(chan error, 1)
	go func() {
		br := bufio.NewReader(client)
		errc <- authenticateUpstream(client, br, wire.UpstreamCredential{Username: "u", Password: "topsecret", Database: "override"}, "ignored")
	}()

	srv := bufio.NewReader(server)
	params := readStartupOnServer(t, srv)
	if params["database"] != "override" {
		t.Fatalf("creds.Database should override startup db, got %q", params["database"])
	}
	writeAuth(t, server, authCleartextPassword, nil)
	typ, payload := readFrontendOnServer(t, srv)
	if typ != msgPassword {
		t.Fatalf("expected PasswordMessage, got %q", string(rune(typ)))
	}
	if got := strings.TrimRight(string(payload), "\x00"); got != "topsecret" {
		t.Fatalf("cleartext password = %q", got)
	}
	writeAuth(t, server, authOK, nil)

	if err := <-errc; err != nil {
		t.Fatalf("authenticateUpstream(cleartext): %v", err)
	}
}

func TestAuthenticateUpstreamMD5(t *testing.T) {
	client, server := net.Pipe()
	defer client.Close()
	defer server.Close()
	deadline(t, client, server)

	errc := make(chan error, 1)
	go func() {
		br := bufio.NewReader(client)
		errc <- authenticateUpstream(client, br, wire.UpstreamCredential{Username: "svc", Password: "hunter2"}, "db")
	}()

	srv := bufio.NewReader(server)
	_ = readStartupOnServer(t, srv)
	salt := []byte{0xde, 0xad, 0xbe, 0xef}
	writeAuth(t, server, authMD5Password, salt)
	typ, payload := readFrontendOnServer(t, srv)
	if typ != msgPassword {
		t.Fatalf("expected PasswordMessage")
	}
	got := strings.TrimRight(string(payload), "\x00")
	if want := md5Password("svc", "hunter2", salt); got != want {
		t.Fatalf("md5 response = %q want %q", got, want)
	}
	writeAuth(t, server, authOK, nil)

	if err := <-errc; err != nil {
		t.Fatalf("authenticateUpstream(md5): %v", err)
	}
}

func TestAuthenticateUpstreamSCRAM(t *testing.T) {
	const password = "br0kered-Pa$$"
	client, server := net.Pipe()
	defer client.Close()
	defer server.Close()
	deadline(t, client, server)

	errc := make(chan error, 1)
	go func() {
		br := bufio.NewReader(client)
		errc <- authenticateUpstream(client, br, wire.UpstreamCredential{Username: "svc", Password: password}, "db")
	}()

	if err := scramServerHandshake(server, password); err != nil {
		t.Fatalf("scram server harness: %v", err)
	}
	if err := <-errc; err != nil {
		t.Fatalf("authenticateUpstream(scram): %v", err)
	}
}

func TestAuthenticateUpstreamSCRAMWrongPassword(t *testing.T) {
	client, server := net.Pipe()
	defer client.Close()
	defer server.Close()
	deadline(t, client, server)

	errc := make(chan error, 1)
	go func() {
		br := bufio.NewReader(client)
		errc <- authenticateUpstream(client, br, wire.UpstreamCredential{Username: "svc", Password: "wrong"}, "db")
	}()

	// Server computes with the real password; the client's proof will not verify, the harness
	// reports it, and authenticateUpstream should surface an auth failure.
	err := scramServerHandshake(server, "right")
	clientErr := <-errc
	if err == nil && clientErr == nil {
		t.Fatal("expected SCRAM to fail with a wrong password")
	}
}

func TestAuthenticateUpstreamErrorResponse(t *testing.T) {
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
	// ErrorResponse: fields are <type byte><cstring>..., terminated by an empty field.
	payload := []byte{'S'}
	payload = append(payload, "FATAL"...)
	payload = append(payload, 0)
	payload = append(payload, 'M')
	payload = append(payload, "password authentication failed"...)
	payload = append(payload, 0, 0)
	writeMsg(t, server, msgErrorResponse, payload)

	err := <-errc
	if err == nil || !strings.Contains(err.Error(), "password authentication failed") {
		t.Fatalf("expected upstream error surfaced, got %v", err)
	}
}

func TestReadStartupParamsAndClientPassword(t *testing.T) {
	client, server := net.Pipe()
	defer client.Close()
	defer server.Close()
	deadline(t, client, server)

	go func() {
		// Client: send StartupMessage, then answer the cleartext request with a token.
		_ = writeStartupMessage(server, "alice", "appdb")
		srv := bufio.NewReader(server)
		typ, payload, _ := readBackendMessage(srv)
		if typ == msgAuthentication && binary.BigEndian.Uint32(payload[0:4]) == authCleartextPassword {
			_ = writePasswordMessage(server, "curlix-session-token-xyz")
		}
		// Expect AuthenticationOk after upstream success.
		_, _, _ = readBackendMessage(srv)
	}()

	cr := bufio.NewReader(client)
	params, err := readStartupParams(cr)
	if err != nil {
		t.Fatalf("readStartupParams: %v", err)
	}
	if params["user"] != "alice" || params["database"] != "appdb" {
		t.Fatalf("params = %v", params)
	}
	token, err := requestClientPassword(client, cr)
	if err != nil {
		t.Fatalf("requestClientPassword: %v", err)
	}
	if token != "curlix-session-token-xyz" {
		t.Fatalf("token = %q", token)
	}
	if err := sendClientAuthOK(client); err != nil {
		t.Fatalf("sendClientAuthOK: %v", err)
	}
}

// TestProxyInjectEndToEnd drives the full credential-handoff path: the client presents an opaque
// token (not a DB password), the agent terminates that login, resolves an upstream credential,
// authenticates upstream over SCRAM-SHA-256, and then masks the result row before it reaches the
// client — proving auth handoff and masking compose.
func TestProxyInjectEndToEnd(t *testing.T) {
	const upstreamPassword = "minted-by-broker"
	clientEnd, agentClient := net.Pipe()
	agentUpstream, upstreamEnd := net.Pipe()
	defer clientEnd.Close()
	defer agentUpstream.Close()
	deadline(t, clientEnd, agentClient, agentUpstream, upstreamEnd)

	resolve := func(_ context.Context, startup map[string]string, secret string) (wire.UpstreamCredential, error) {
		if secret != "good-session-token" {
			return wire.UpstreamCredential{}, errors.New("bad token")
		}
		if startup["user"] != "alice" {
			return wire.UpstreamCredential{}, errors.New("unexpected user")
		}
		return wire.UpstreamCredential{Username: "svc", Password: upstreamPassword}, nil
	}

	proxyErr := make(chan error, 1)
	go func() {
		proxyErr <- (&Engine{}).ProxyInject(context.Background(), agentClient, agentUpstream, columnMasker{redact: map[string]bool{"email": true}}, resolve)
	}()

	// Upstream side: complete SCRAM, then emit one masked-eligible result row.
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

	// Client side: send startup, answer the cleartext request with the token, then read the stream.
	if err := writeStartupMessage(clientEnd, "alice", "appdb"); err != nil {
		t.Fatalf("client startup: %v", err)
	}
	cr := bufio.NewReader(clientEnd)
	typ, payload, err := readBackendMessage(cr)
	if err != nil {
		t.Fatalf("client read auth req: %v", err)
	}
	if typ != msgAuthentication || binary.BigEndian.Uint32(payload[0:4]) != authCleartextPassword {
		t.Fatalf("expected cleartext password request, got typ=%q", string(rune(typ)))
	}
	if err := writePasswordMessage(clientEnd, "good-session-token"); err != nil {
		t.Fatalf("client send token: %v", err)
	}

	var sawMaskedEmail, sawPlaintext bool
	for i := 0; i < 5; i++ {
		typ, payload, err = readBackendMessage(cr)
		if err != nil {
			break
		}
		if typ == 'D' {
			if strings.Contains(string(payload), "***") {
				sawMaskedEmail = true
			}
			if strings.Contains(string(payload), "alice@example.com") {
				sawPlaintext = true
			}
		}
		if typ == 'Z' {
			break
		}
	}
	if err := <-upErr; err != nil {
		t.Fatalf("upstream harness: %v", err)
	}
	if !sawMaskedEmail {
		t.Fatal("expected the email column to be masked in the relayed row")
	}
	if sawPlaintext {
		t.Fatal("plaintext email leaked through the injecting proxy")
	}
}

// --- test harness ----------------------------------------------------------

func deadline(t *testing.T, conns ...net.Conn) {
	t.Helper()
	dl := time.Now().Add(5 * time.Second)
	for _, c := range conns {
		_ = c.SetDeadline(dl)
	}
}

func readStartupOnServer(t *testing.T, br *bufio.Reader) map[string]string {
	t.Helper()
	var hdr [8]byte
	if _, err := io.ReadFull(br, hdr[:]); err != nil {
		t.Fatalf("read startup header: %v", err)
	}
	length := binary.BigEndian.Uint32(hdr[0:4])
	body := make([]byte, int(length)-8)
	if _, err := io.ReadFull(br, body); err != nil {
		t.Fatalf("read startup body: %v", err)
	}
	params := map[string]string{}
	parts := strings.Split(string(body), "\x00")
	for i := 0; i+1 < len(parts); i += 2 {
		if parts[i] != "" {
			params[parts[i]] = parts[i+1]
		}
	}
	return params
}

func readFrontendOnServer(t *testing.T, br *bufio.Reader) (byte, []byte) {
	t.Helper()
	typ, payload, err := readBackendMessage(br) // same framing for typed frontend messages
	if err != nil {
		t.Fatalf("read frontend message: %v", err)
	}
	return typ, payload
}

func writeAuth(t *testing.T, w io.Writer, code uint32, extra []byte) {
	t.Helper()
	payload := make([]byte, 4+len(extra))
	binary.BigEndian.PutUint32(payload[0:4], code)
	copy(payload[4:], extra)
	writeMsg(t, w, msgAuthentication, payload)
}

func writeMsg(t *testing.T, w io.Writer, typ byte, payload []byte) {
	t.Helper()
	hdr := make([]byte, 5)
	hdr[0] = typ
	binary.BigEndian.PutUint32(hdr[1:5], uint32(len(payload)+4))
	if _, err := w.Write(hdr); err != nil {
		t.Fatalf("write header: %v", err)
	}
	if _, err := w.Write(payload); err != nil {
		t.Fatalf("write payload: %v", err)
	}
}

// scramServerHandshake runs the SCRAM-SHA-256 *server* side against our client implementation,
// authenticating with the given password. It returns an error if the client's proof does not verify.
func scramServerHandshake(server net.Conn, password string) error {
	srv := bufio.NewReader(server)
	// Consume the StartupMessage.
	var hdr [8]byte
	if _, err := io.ReadFull(srv, hdr[:]); err != nil {
		return err
	}
	body := make([]byte, int(binary.BigEndian.Uint32(hdr[0:4]))-8)
	if _, err := io.ReadFull(srv, body); err != nil {
		return err
	}
	// Offer SCRAM-SHA-256.
	writeAuthRaw(server, authSASL, append([]byte(scramSHA256), 0))

	// Read SASLInitialResponse.
	typ, payload, err := readBackendMessage(srv)
	if err != nil {
		return err
	}
	if typ != msgPassword {
		return errors.New("expected SASLInitialResponse")
	}
	// payload: mechanism cstring + int32 len + client-first.
	zero := indexZero(payload, 0)
	rest := payload[zero+1:]
	respLen := int(binary.BigEndian.Uint32(rest[0:4]))
	clientFirst := string(rest[4 : 4+respLen])
	clientFirstBare := strings.TrimPrefix(clientFirst, "n,,")
	clientNonce := parseSCRAMAttrs(clientFirstBare)["r"]

	salt := []byte("0123456789abcdef")
	iter := 4096
	serverNonce := clientNonce + "serverpart"
	serverFirst := "r=" + serverNonce + ",s=" + base64.StdEncoding.EncodeToString(salt) + ",i=" + strconv.Itoa(iter)
	writeAuthRaw(server, authSASLContinue, []byte(serverFirst))

	// Read client-final.
	typ, payload, err = readBackendMessage(srv)
	if err != nil {
		return err
	}
	if typ != msgPassword {
		return errors.New("expected SASLResponse")
	}
	clientFinal := string(payload)
	clientFinalWithoutProof := strings.Split(clientFinal, ",p=")[0]
	proofB64 := strings.Split(clientFinal, ",p=")[1]
	gotProof, _ := base64.StdEncoding.DecodeString(proofB64)

	saltedPassword := pbkdf2SHA256([]byte(password), salt, iter, sha256.Size)
	clientKey := hmacSHA256(saltedPassword, []byte("Client Key"))
	storedKey := sha256.Sum256(clientKey)
	authMessage := clientFirstBare + "," + serverFirst + "," + clientFinalWithoutProof
	clientSignature := hmacSHA256(storedKey[:], []byte(authMessage))
	// Recover the client key the client used and verify it matches our stored key.
	recovered := make([]byte, len(gotProof))
	for i := range gotProof {
		recovered[i] = gotProof[i] ^ clientSignature[i]
	}
	recoveredStored := sha256.Sum256(recovered)
	if string(recoveredStored[:]) != string(storedKey[:]) {
		// Wrong password: send an error so the client exchange fails cleanly.
		writeErr(server, "invalid SCRAM proof")
		return errors.New("client proof did not verify")
	}
	serverKey := hmacSHA256(saltedPassword, []byte("Server Key"))
	serverSignature := hmacSHA256(serverKey, []byte(authMessage))
	writeAuthRaw(server, authSASLFinal, []byte("v="+base64.StdEncoding.EncodeToString(serverSignature)))
	writeAuthRaw(server, authOK, nil)
	return nil
}

func writeAuthRaw(w io.Writer, code uint32, extra []byte) {
	payload := make([]byte, 4+len(extra))
	binary.BigEndian.PutUint32(payload[0:4], code)
	copy(payload[4:], extra)
	hdr := make([]byte, 5)
	hdr[0] = msgAuthentication
	binary.BigEndian.PutUint32(hdr[1:5], uint32(len(payload)+4))
	_, _ = w.Write(hdr)
	_, _ = w.Write(payload)
}

func writeErr(w io.Writer, msg string) {
	payload := []byte{'M'}
	payload = append(payload, msg...)
	payload = append(payload, 0, 0)
	hdr := make([]byte, 5)
	hdr[0] = msgErrorResponse
	binary.BigEndian.PutUint32(hdr[1:5], uint32(len(payload)+4))
	_, _ = w.Write(hdr)
	_, _ = w.Write(payload)
}
