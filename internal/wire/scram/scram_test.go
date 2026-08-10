package scram

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha1" //nolint:gosec // test-side fake SCRAM-SHA-1 server
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"hash"
	"strconv"
	"strings"
	"testing"
)

// fakeServer implements the server role of RFC 5802 for one mechanism, used to drive
// ClientConversation end-to-end without a real database.
type fakeServer struct {
	mechanism string
	newHash   func() hash.Hash
	username  string
	password  string
	iter      int

	serverNonce string
	clientFirst string
	serverFirst string
}

func newFakeServer(t *testing.T, mechanism, username, password string, iter int) *fakeServer {
	t.Helper()
	var newHash func() hash.Hash
	switch mechanism {
	case SHA1:
		newHash = sha1.New
	case SHA256:
		newHash = sha256.New
	default:
		t.Fatalf("unsupported mechanism %q", mechanism)
	}
	nonce := make([]byte, 18)
	if _, err := rand.Read(nonce); err != nil {
		t.Fatalf("nonce: %v", err)
	}
	return &fakeServer{
		mechanism:   mechanism,
		newHash:     newHash,
		username:    username,
		password:    password,
		iter:        iter,
		serverNonce: base64.StdEncoding.EncodeToString(nonce),
	}
}

// firstMessage takes the client-first-message (with gs2 header stripped by the caller, matching
// how Postgres/Mongo strip their own framing before handing the bare message to the server) and
// returns the server-first-message.
func (s *fakeServer) firstMessage(clientFirstBare string) string {
	s.clientFirst = clientFirstBare
	attrs := parseAttrs(clientFirstBare)
	clientNonce := attrs["r"]
	combined := clientNonce + s.serverNonce
	salt := []byte("fixed-test-salt-0123456789abcdef")
	s.serverFirst = "r=" + combined + ",s=" + base64.StdEncoding.EncodeToString(salt) + ",i=" + strconv.Itoa(s.iter)
	return s.serverFirst
}

// finalMessage verifies the client's proof and, if valid, returns the server-final-message
// (verifier). Returns ("", false) on a bad proof.
func (s *fakeServer) finalMessage(clientFinal string) (string, bool) {
	attrs := parseAttrs(clientFinal)
	proofB64 := attrs["p"]
	proof, err := base64.StdEncoding.DecodeString(proofB64)
	if err != nil {
		return "", false
	}
	clientFinalWithoutProof := clientFinal[:strings.LastIndex(clientFinal, ",p=")]

	salt := []byte("fixed-test-salt-0123456789abcdef")
	saltedPassword := pbkdf2(s.newHash, []byte(s.password), salt, s.iter, s.newHash().Size())
	authMessage := s.clientFirst + "," + s.serverFirst + "," + clientFinalWithoutProof

	clientKey := s.hmac(saltedPassword, "Client Key")
	storedKey := s.hash(clientKey)
	clientSignature := s.hmac(storedKey, authMessage)
	wantClientKey := make([]byte, len(clientKey))
	for i := range proof {
		wantClientKey[i] = proof[i] ^ clientSignature[i]
	}
	if s.hash(wantClientKey) == nil {
		return "", false
	}
	gotStoredKey := s.hash(wantClientKey)
	if !hmac.Equal(gotStoredKey, storedKey) {
		return "", false
	}

	serverKey := s.hmac(saltedPassword, "Server Key")
	serverSig := s.hmac(serverKey, authMessage)
	return "v=" + base64.StdEncoding.EncodeToString(serverSig), true
}

func (s *fakeServer) hash(b []byte) []byte {
	h := s.newHash()
	h.Write(b)
	return h.Sum(nil)
}

func (s *fakeServer) hmac(key []byte, msg string) []byte {
	h := hmac.New(s.newHash, key)
	h.Write([]byte(msg))
	return h.Sum(nil)
}

func runFullExchange(t *testing.T, mechanism, username, password string) error {
	t.Helper()
	conv, err := NewClientConversation(mechanism, username, password)
	if err != nil {
		t.Fatalf("NewClientConversation: %v", err)
	}
	server := newFakeServer(t, mechanism, username, password, 4096)

	first := conv.ClientFirstMessage()
	// Strip the gs2 header ("n,,") the same way a real server would never see it as part of the
	// bare message it parses attributes from.
	bare := strings.TrimPrefix(first, "n,,")

	serverFirst := server.firstMessage(bare)
	clientFinal, err := conv.Step2(serverFirst)
	if err != nil {
		return err
	}
	serverFinal, ok := server.finalMessage(clientFinal)
	if !ok {
		t.Fatal("fake server rejected client proof")
	}
	return conv.Step3(serverFinal)
}

func TestClientConversation_SHA256_FullExchangeSucceeds(t *testing.T) {
	if err := runFullExchange(t, SHA256, "alice", "correct-password"); err != nil {
		t.Fatalf("expected successful SCRAM-SHA-256 exchange, got: %v", err)
	}
}

func TestClientConversation_SHA1_FullExchangeSucceeds(t *testing.T) {
	if err := runFullExchange(t, SHA1, "alice", "correct-password"); err != nil {
		t.Fatalf("expected successful SCRAM-SHA-1 exchange, got: %v", err)
	}
}

func TestClientConversation_WrongPasswordFailsServerVerification(t *testing.T) {
	conv, err := NewClientConversation(SHA256, "alice", "wrong-password")
	if err != nil {
		t.Fatalf("NewClientConversation: %v", err)
	}
	server := newFakeServer(t, SHA256, "alice", "correct-password", 4096)

	first := conv.ClientFirstMessage()
	bare := strings.TrimPrefix(first, "n,,")
	serverFirst := server.firstMessage(bare)
	clientFinal, err := conv.Step2(serverFirst)
	if err != nil {
		t.Fatalf("Step2: %v", err)
	}
	if _, ok := server.finalMessage(clientFinal); ok {
		t.Fatal("expected the fake server to reject a wrong-password proof")
	}
}

func TestClientConversation_Step3RejectsForgedServerSignature(t *testing.T) {
	conv, err := NewClientConversation(SHA256, "alice", "correct-password")
	if err != nil {
		t.Fatalf("NewClientConversation: %v", err)
	}
	server := newFakeServer(t, SHA256, "alice", "correct-password", 4096)

	first := conv.ClientFirstMessage()
	bare := strings.TrimPrefix(first, "n,,")
	serverFirst := server.firstMessage(bare)
	if _, err := conv.Step2(serverFirst); err != nil {
		t.Fatalf("Step2: %v", err)
	}
	// A forged/garbage server-final-message must be rejected — this is the check that defends
	// against a MITM upstream that accepted the client but isn't the real server.
	if err := conv.Step3("v=" + base64.StdEncoding.EncodeToString([]byte("not-the-real-signature!!"))); err == nil {
		t.Fatal("expected Step3 to reject a forged server signature")
	}
}

func TestNewClientConversation_RejectsUnknownMechanism(t *testing.T) {
	if _, err := NewClientConversation("SCRAM-SHA-512", "alice", "pw"); err == nil {
		t.Fatal("expected an error for an unsupported mechanism")
	}
}

func TestClientConversation_Step2RejectsMalformedServerFirst(t *testing.T) {
	conv, err := NewClientConversation(SHA256, "alice", "pw")
	if err != nil {
		t.Fatalf("NewClientConversation: %v", err)
	}
	conv.ClientFirstMessage()
	if _, err := conv.Step2("garbage-no-attrs"); err == nil {
		t.Fatal("expected an error for a malformed server-first message")
	}
}

func TestClientConversation_Step2RejectsNonExtendingNonce(t *testing.T) {
	conv, err := NewClientConversation(SHA256, "alice", "pw")
	if err != nil {
		t.Fatalf("NewClientConversation: %v", err)
	}
	conv.ClientFirstMessage()
	salt := base64.StdEncoding.EncodeToString([]byte("0123456789abcdef"))
	_, err = conv.Step2("r=completely-different-nonce,s=" + salt + ",i=4096")
	if err == nil {
		t.Fatal("expected an error when the server nonce does not extend the client nonce")
	}
}

func TestEscapeSCRAMName(t *testing.T) {
	if got := escapeSCRAMName("a=b,c"); got != "a=3Db=2Cc" {
		t.Fatalf("escapeSCRAMName = %q, want a=3Db=2Cc", got)
	}
}

func TestPBKDF2_SHA256_RFCVectors(t *testing.T) {
	// Well-known PBKDF2-HMAC-SHA256 test vectors (P="password", S="salt", dkLen=32). Moved here
	// from postgres/auth_test.go when the math was extracted from scramClientExchange.
	got := hex.EncodeToString(pbkdf2(sha256.New, []byte("password"), []byte("salt"), 1, 32))
	want := "120fb6cffcf8b32c43e7225256c4f837a86548c92ccc35480805987cb70be17b"
	if got != want {
		t.Fatalf("pbkdf2 c=1: got %s want %s", got, want)
	}
	got2 := hex.EncodeToString(pbkdf2(sha256.New, []byte("password"), []byte("salt"), 2, 32))
	want2 := "ae4d0c95af6b46d32d0adff928f06dd02a303f8ef3c251dfd6e2d85a95474c43"
	if got2 != want2 {
		t.Fatalf("pbkdf2 c=2: got %s want %s", got2, want2)
	}
}
