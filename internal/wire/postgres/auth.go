// Credential handoff (design "skybridge-go-wire-proxy" §7 phase 3) for Postgres.
//
// In the default proxy path the agent forwards the client->upstream auth handshake verbatim, so the
// native client presents a real database credential. Credential *injection* flips that: the client
// presents an opaque curlix session token as its password, the agent terminates that client auth
// locally, exchanges the token for a freshly-minted upstream credential, and then ORIGINATES its own
// upstream auth handshake with that credential. The client therefore never holds a credential the
// database would accept directly.
//
// This file implements the two halves of that, stdlib-only:
//
//   - client-side termination: read the StartupMessage, request a cleartext password, return it as
//     the presented secret (the agent answers AuthenticationOk only after upstream auth succeeds).
//   - upstream-side origination: send our own StartupMessage and complete the server's challenge,
//     supporting AuthenticationOk (trust), AuthenticationCleartextPassword, AuthenticationMD5Password
//     and SASL/SCRAM-SHA-256 (the Postgres 14+ default, used by modern RDS/Aurora and pgvector:pg15).
//
// SCRAM channel binding is not used (we speak plaintext to the upstream over the trusted in-network
// path for now; client/upstream TLS is a later phase), so the advertised/selected mechanism is
// "SCRAM-SHA-256", never "SCRAM-SHA-256-PLUS".
package postgres

import (
	"bufio"
	"crypto/hmac"
	"crypto/md5"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"strconv"
	"strings"

	"github.com/curlix-io/skybridge/internal/wire"
)

// Frontend/backend message types and authentication sub-codes used during the handshake.
const (
	msgAuthentication = 'R' // backend: authentication request / ok
	msgPassword       = 'p' // frontend: PasswordMessage / SASLInitialResponse / SASLResponse
	msgErrorResponse  = 'E' // backend: ErrorResponse

	authOK                = 0
	authCleartextPassword = 3
	authMD5Password       = 5
	authSASL              = 10
	authSASLContinue      = 11
	authSASLFinal         = 12

	scramSHA256 = "SCRAM-SHA-256"

	// startupProtocolV3 is the protocol version in the StartupMessage (major 3, minor 0).
	startupProtocolV3 = 196608
)

// readStartupParams reads one StartupMessage from cr (which negotiateStartup has left buffered,
// SSL/GSS frames already declined) and returns its parameter map (e.g. "user", "database"). The
// frame is fully consumed; it is NOT forwarded upstream, because the agent originates its own
// startup with the injected credential.
func readStartupParams(cr *bufio.Reader) (map[string]string, error) {
	var hdr [8]byte
	if _, err := io.ReadFull(cr, hdr[:]); err != nil {
		return nil, err
	}
	length := binary.BigEndian.Uint32(hdr[0:4])
	version := binary.BigEndian.Uint32(hdr[4:8])
	if version != startupProtocolV3 {
		return nil, fmt.Errorf("postgres: unsupported startup protocol %d (want %d)", version, startupProtocolV3)
	}
	if length < 8 || length > sniffStartupCap {
		return nil, errProtocol
	}
	body := make([]byte, int(length)-8)
	if _, err := io.ReadFull(cr, body); err != nil {
		return nil, err
	}
	params := map[string]string{}
	parts := strings.Split(string(body), "\x00")
	for i := 0; i+1 < len(parts); i += 2 {
		if parts[i] == "" {
			continue
		}
		params[parts[i]] = parts[i+1]
	}
	return params, nil
}

// sniffStartupCap bounds the StartupMessage size we will buffer (defensive; real ones are tiny).
const sniffStartupCap = 64 << 10

// requestClientPassword asks the connected client for a cleartext password and returns it. It reads
// the client's reply from br (the same buffered reader negotiateStartup/readStartupParams already use
// on the client connection) so no buffered bytes are dropped. The returned value is the opaque curlix
// session token the client presented; the agent does not send AuthenticationOk here — it does so only
// after the upstream auth succeeds (sendClientAuthOK).
func requestClientPassword(w io.Writer, br *bufio.Reader) (string, error) {
	// AuthenticationCleartextPassword: 'R' + int32 len(8) + int32 code(3).
	var msg [9]byte
	msg[0] = msgAuthentication
	binary.BigEndian.PutUint32(msg[1:5], 8)
	binary.BigEndian.PutUint32(msg[5:9], authCleartextPassword)
	if _, err := w.Write(msg[:]); err != nil {
		return "", err
	}
	typ, payload, err := readBackendMessage(br)
	if err != nil {
		return "", err
	}
	if typ != msgPassword {
		return "", fmt.Errorf("postgres: expected PasswordMessage from client, got %q", string(rune(typ)))
	}
	// PasswordMessage payload is the null-terminated password string.
	return strings.TrimRight(string(payload), "\x00"), nil
}

// sendClientAuthOK tells the client its authentication to the proxy succeeded. After this the proxy
// forwards the upstream's post-auth messages (ParameterStatus, BackendKeyData, ReadyForQuery, …).
func sendClientAuthOK(w io.Writer) error {
	var msg [9]byte
	msg[0] = msgAuthentication
	binary.BigEndian.PutUint32(msg[1:5], 8)
	binary.BigEndian.PutUint32(msg[5:9], authOK)
	_, err := w.Write(msg[:])
	return err
}

// authenticateUpstream originates a fresh Postgres connection auth against the upstream using creds.
// It writes a StartupMessage and completes whatever authentication the backend requests, returning
// once AuthenticationOk is received (leaving the subsequent ParameterStatus/BackendKeyData/
// ReadyForQuery messages unread in br for the proxy to forward to the client). startupDatabase is
// the database to request (creds.Database overrides the client's requested DB when set).
func authenticateUpstream(upstream io.Writer, br *bufio.Reader, creds wire.UpstreamCredential, startupDatabase string) error {
	db := strings.TrimSpace(creds.Database)
	if db == "" {
		db = startupDatabase
	}
	if err := writeStartupMessage(upstream, creds.Username, db); err != nil {
		return err
	}
	for {
		typ, payload, err := readBackendMessage(br)
		if err != nil {
			return err
		}
		if typ == msgErrorResponse {
			return fmt.Errorf("postgres upstream rejected auth: %s", parseErrorResponse(payload))
		}
		if typ != msgAuthentication {
			return fmt.Errorf("postgres: expected Authentication message, got %q", string(rune(typ)))
		}
		if len(payload) < 4 {
			return errProtocol
		}
		code := binary.BigEndian.Uint32(payload[0:4])
		switch code {
		case authOK:
			return nil
		case authCleartextPassword:
			if err := writePasswordMessage(upstream, creds.Password); err != nil {
				return err
			}
		case authMD5Password:
			if len(payload) < 8 {
				return errProtocol
			}
			salt := payload[4:8]
			if err := writePasswordMessage(upstream, md5Password(creds.Username, creds.Password, salt)); err != nil {
				return err
			}
		case authSASL:
			if err := scramClientExchange(upstream, br, payload[4:], creds.Password); err != nil {
				return err
			}
			// scramClientExchange returns after AuthenticationSASLFinal; loop again to consume the
			// trailing AuthenticationOk.
		default:
			return fmt.Errorf("postgres: unsupported authentication method %d from upstream", code)
		}
	}
}

// writeStartupMessage sends a v3 StartupMessage requesting the given user and database.
func writeStartupMessage(w io.Writer, user, database string) error {
	var body []byte
	add := func(k, v string) {
		body = append(body, k...)
		body = append(body, 0)
		body = append(body, v...)
		body = append(body, 0)
	}
	add("user", user)
	if database != "" {
		add("database", database)
	}
	body = append(body, 0) // terminating empty key

	out := make([]byte, 8+len(body))
	binary.BigEndian.PutUint32(out[0:4], uint32(8+len(body)))
	binary.BigEndian.PutUint32(out[4:8], startupProtocolV3)
	copy(out[8:], body)
	_, err := w.Write(out)
	return err
}

// writePasswordMessage sends a frontend PasswordMessage ('p') carrying a null-terminated string.
func writePasswordMessage(w io.Writer, password string) error {
	return writeFrontend(w, msgPassword, append([]byte(password), 0))
}

// writeFrontend writes a typed frontend message: type byte + int32 length (incl. itself) + payload.
func writeFrontend(w io.Writer, typ byte, payload []byte) error {
	hdr := make([]byte, 5)
	hdr[0] = typ
	binary.BigEndian.PutUint32(hdr[1:5], uint32(len(payload)+4))
	if _, err := w.Write(hdr); err != nil {
		return err
	}
	if len(payload) > 0 {
		_, err := w.Write(payload)
		return err
	}
	return nil
}

// readBackendMessage reads one typed backend message (type + length-prefixed payload).
func readBackendMessage(br *bufio.Reader) (byte, []byte, error) {
	var hdr [5]byte
	if _, err := io.ReadFull(br, hdr[:]); err != nil {
		return 0, nil, err
	}
	length := binary.BigEndian.Uint32(hdr[1:5])
	if length < 4 {
		return 0, nil, errProtocol
	}
	payload := make([]byte, int(length)-4)
	if _, err := io.ReadFull(br, payload); err != nil {
		return 0, nil, err
	}
	return hdr[0], payload, nil
}

// md5Password computes the Postgres md5 auth response: "md5" + md5hex(md5hex(password+user)+salt).
func md5Password(user, password string, salt []byte) string {
	inner := md5Hex([]byte(password + user))
	outer := md5Hex(append([]byte(inner), salt...))
	return "md5" + outer
}

func md5Hex(b []byte) string {
	sum := md5.Sum(b)
	const hexdigits = "0123456789abcdef"
	out := make([]byte, len(sum)*2)
	for i, c := range sum {
		out[i*2] = hexdigits[c>>4]
		out[i*2+1] = hexdigits[c&0x0f]
	}
	return string(out)
}

// scramClientExchange performs the SCRAM-SHA-256 client side of SASL auth against the upstream. On
// entry saslPayload is the AuthenticationSASL body (the null-separated list of mechanisms the server
// offers). It returns after sending the client-final message and verifying the server signature from
// AuthenticationSASLFinal; the trailing AuthenticationOk is consumed by the caller's loop.
func scramClientExchange(upstream io.Writer, br *bufio.Reader, saslPayload []byte, password string) error {
	if !mechanismOffered(saslPayload, scramSHA256) {
		return fmt.Errorf("postgres: upstream did not offer %s (channel binding unsupported)", scramSHA256)
	}
	clientNonce, err := randomNonce()
	if err != nil {
		return err
	}
	clientFirstBare := "n=,r=" + clientNonce
	// SASLInitialResponse: mechanism name (cstring) + int32 length of response + response bytes.
	gs2 := "n,,"
	initial := gs2 + clientFirstBare
	var buf []byte
	buf = append(buf, scramSHA256...)
	buf = append(buf, 0)
	var l [4]byte
	binary.BigEndian.PutUint32(l[:], uint32(len(initial)))
	buf = append(buf, l[:]...)
	buf = append(buf, initial...)
	if err := writeFrontend(upstream, msgPassword, buf); err != nil {
		return err
	}

	typ, payload, err := readBackendMessage(br)
	if err != nil {
		return err
	}
	if typ == msgErrorResponse {
		return fmt.Errorf("postgres upstream rejected SCRAM: %s", parseErrorResponse(payload))
	}
	if typ != msgAuthentication || len(payload) < 4 || binary.BigEndian.Uint32(payload[0:4]) != authSASLContinue {
		return errors.New("postgres: expected AuthenticationSASLContinue")
	}
	serverFirst := string(payload[4:])
	attrs := parseSCRAMAttrs(serverFirst)
	combinedNonce := attrs["r"]
	saltB64 := attrs["s"]
	iterStr := attrs["i"]
	if combinedNonce == "" || saltB64 == "" || iterStr == "" {
		return errors.New("postgres: malformed SCRAM server-first message")
	}
	if !strings.HasPrefix(combinedNonce, clientNonce) {
		return errors.New("postgres: SCRAM server nonce does not extend client nonce")
	}
	salt, err := base64.StdEncoding.DecodeString(saltB64)
	if err != nil {
		return fmt.Errorf("postgres: bad SCRAM salt: %w", err)
	}
	iter, err := strconv.Atoi(iterStr)
	if err != nil || iter <= 0 {
		return fmt.Errorf("postgres: bad SCRAM iteration count %q", iterStr)
	}

	saltedPassword := pbkdf2SHA256([]byte(saslPrep(password)), salt, iter, sha256.Size)
	clientKey := hmacSHA256(saltedPassword, []byte("Client Key"))
	storedKey := sha256.Sum256(clientKey)

	channelBinding := base64.StdEncoding.EncodeToString([]byte(gs2)) // "biws"
	clientFinalWithoutProof := "c=" + channelBinding + ",r=" + combinedNonce
	authMessage := clientFirstBare + "," + serverFirst + "," + clientFinalWithoutProof

	clientSignature := hmacSHA256(storedKey[:], []byte(authMessage))
	clientProof := make([]byte, len(clientKey))
	for i := range clientKey {
		clientProof[i] = clientKey[i] ^ clientSignature[i]
	}
	clientFinal := clientFinalWithoutProof + ",p=" + base64.StdEncoding.EncodeToString(clientProof)
	if err := writeFrontend(upstream, msgPassword, []byte(clientFinal)); err != nil {
		return err
	}

	typ, payload, err = readBackendMessage(br)
	if err != nil {
		return err
	}
	if typ == msgErrorResponse {
		return fmt.Errorf("postgres upstream rejected SCRAM proof: %s", parseErrorResponse(payload))
	}
	if typ != msgAuthentication || len(payload) < 4 || binary.BigEndian.Uint32(payload[0:4]) != authSASLFinal {
		return errors.New("postgres: expected AuthenticationSASLFinal")
	}
	finalAttrs := parseSCRAMAttrs(string(payload[4:]))
	serverSigB64 := finalAttrs["v"]
	gotSig, err := base64.StdEncoding.DecodeString(serverSigB64)
	if err != nil {
		return fmt.Errorf("postgres: bad SCRAM server signature: %w", err)
	}
	serverKey := hmacSHA256(saltedPassword, []byte("Server Key"))
	wantSig := hmacSHA256(serverKey, []byte(authMessage))
	if subtle.ConstantTimeCompare(gotSig, wantSig) != 1 {
		return errors.New("postgres: SCRAM server signature mismatch (wrong password or MITM)")
	}
	return nil
}

func mechanismOffered(payload []byte, mech string) bool {
	for _, m := range strings.Split(string(payload), "\x00") {
		if m == mech {
			return true
		}
	}
	return false
}

func parseSCRAMAttrs(s string) map[string]string {
	out := map[string]string{}
	for _, kv := range strings.Split(s, ",") {
		if i := strings.IndexByte(kv, '='); i > 0 {
			out[kv[:i]] = kv[i+1:]
		}
	}
	return out
}

func randomNonce() (string, error) {
	b := make([]byte, 18)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return base64.StdEncoding.EncodeToString(b), nil
}

func hmacSHA256(key, msg []byte) []byte {
	h := hmac.New(sha256.New, key)
	h.Write(msg)
	return h.Sum(nil)
}

// pbkdf2SHA256 derives a key with PBKDF2-HMAC-SHA256 (RFC 8018), hand-rolled to keep the module
// stdlib-only (no golang.org/x/crypto dependency).
func pbkdf2SHA256(password, salt []byte, iter, keyLen int) []byte {
	hLen := sha256.Size
	numBlocks := (keyLen + hLen - 1) / hLen
	out := make([]byte, 0, numBlocks*hLen)
	var block [4]byte
	for i := 1; i <= numBlocks; i++ {
		binary.BigEndian.PutUint32(block[:], uint32(i))
		u := hmacSHA256(password, append(append([]byte{}, salt...), block[:]...))
		t := make([]byte, len(u))
		copy(t, u)
		for j := 1; j < iter; j++ {
			u = hmacSHA256(password, u)
			for k := range t {
				t[k] ^= u[k]
			}
		}
		out = append(out, t...)
	}
	return out[:keyLen]
}

// saslPrep is a minimal SASLprep: Postgres applies SASLprep to the password, but for the ASCII
// passwords curlix's brokers mint it is the identity function. We deliberately do not pull in a full
// stringprep table; non-ASCII passwords are passed through unchanged (documented limitation).
func saslPrep(password string) string { return password }

// parseErrorResponse extracts the human-readable message ('M' field) from an ErrorResponse payload.
func parseErrorResponse(payload []byte) string {
	for _, field := range strings.Split(string(payload), "\x00") {
		if len(field) > 1 && field[0] == 'M' {
			return field[1:]
		}
	}
	return "unknown error"
}
