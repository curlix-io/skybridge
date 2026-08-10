package mongo

import (
	"bufio"
	"crypto/hmac"
	"crypto/sha1" //nolint:gosec // fake SCRAM-SHA-1 upstream server fixture
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"hash"
	"net"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/curlix-io/skybridge/internal/wire"
)

func deadlineFor(t *testing.T) time.Time {
	t.Helper()
	return time.Now().Add(5 * time.Second)
}

// fakeMongoSCRAMServer implements just enough of the server role of RFC 5802, framed as MongoDB
// saslStart/saslContinue commands over OP_MSG, to drive authenticateUpstream end-to-end without a
// real database. mechanismsAvailable controls which mechanism(s) this fake server accepts —
// requesting anything else gets a MechanismUnavailable (code 334) reply, exercising the SHA-256 ->
// SHA-1 fallback path.
type fakeMongoSCRAMServer struct {
	t                   *testing.T
	rw                  *bufio.ReadWriter
	username, password  string
	mechanismsAvailable map[string]bool
	iter                int
	salt                []byte
	serverNonce         string
	clientFirst         string
	serverFirst         string
	newHash             func() hash.Hash
}

func newFakeMongoSCRAMServer(t *testing.T, conn net.Conn, username, password string, mechanisms ...string) *fakeMongoSCRAMServer {
	t.Helper()
	avail := map[string]bool{}
	for _, m := range mechanisms {
		avail[m] = true
	}
	return &fakeMongoSCRAMServer{
		t:                   t,
		rw:                  bufio.NewReadWriter(bufio.NewReader(conn), bufio.NewWriter(conn)),
		username:            username,
		password:            password,
		mechanismsAvailable: avail,
		iter:                4096,
		salt:                []byte("fixed-test-salt-0123456789abcdef"),
		serverNonce:         "serverfixednonce",
	}
}

// serve handles exactly one saslStart followed by (if the mechanism was accepted) one
// saslContinue, then returns. Call once per authenticateUpstream call under test.
func (s *fakeMongoSCRAMServer) serve() error {
	startMsg, err := readMessage(s.rw.Reader)
	if err != nil {
		return err
	}
	startDoc, ok := parseCommandDocGeneric(startMsg)
	if !ok {
		return errors.New("fake server: bad saslStart")
	}
	requestID := int32(1)
	mechanism := stringField(startDoc, "mechanism")
	if !s.mechanismsAvailable[mechanism] {
		reply := newDoc().
			addDouble("ok", 0).
			addInt32("code", mechanismUnavailableCode).
			addString("codeName", "MechanismUnavailable").
			addString("errmsg", "no credentials available for mechanism "+mechanism).
			bytes()
		return s.writeReply(reply, requestID)
	}
	switch mechanism {
	case "SCRAM-SHA-1":
		s.newHash = sha1.New
	case "SCRAM-SHA-256":
		s.newHash = sha256.New
	default:
		return errors.New("fake server: unsupported mechanism in test")
	}

	clientFirst := string(binaryField(startDoc, "payload"))
	s.clientFirst = strings.TrimPrefix(clientFirst, "n,,")
	attrs := map[string]string{}
	for _, kv := range strings.Split(s.clientFirst, ",") {
		if i := strings.IndexByte(kv, '='); i > 0 {
			attrs[kv[:i]] = kv[i+1:]
		}
	}
	combined := attrs["r"] + s.serverNonce
	s.serverFirst = "r=" + combined + ",s=" + base64.StdEncoding.EncodeToString(s.salt) + ",i=" + strconv.Itoa(s.iter)

	startReply := newDoc().
		addInt32("conversationId", 7).
		addBool("done", false).
		addBinary("payload", []byte(s.serverFirst)).
		addDouble("ok", 1).
		bytes()
	if err := s.writeReply(startReply, requestID); err != nil {
		return err
	}

	continueMsg, err := readMessage(s.rw.Reader)
	if err != nil {
		return err
	}
	continueDoc, ok := parseCommandDocGeneric(continueMsg)
	if !ok {
		return errors.New("fake server: bad saslContinue")
	}
	requestID = int32(binary.LittleEndian.Uint32(continueMsg[4:8]))
	clientFinal := string(binaryField(continueDoc, "payload"))
	proofB64 := strings.Split(clientFinal, ",p=")[1]
	proof, err := base64.StdEncoding.DecodeString(proofB64)
	if err != nil {
		return err
	}
	clientFinalWithoutProof := clientFinal[:strings.LastIndex(clientFinal, ",p=")]

	saltedPassword := pbkdf2ForTest(s.newHash, []byte(s.password), s.salt, s.iter, s.newHash().Size())
	authMessage := s.clientFirst + "," + s.serverFirst + "," + clientFinalWithoutProof
	clientKey := s.hmac(saltedPassword, "Client Key")
	storedKey := s.hash(clientKey)
	clientSignature := s.hmac(storedKey, authMessage)
	recoveredKey := make([]byte, len(proof))
	for i := range proof {
		recoveredKey[i] = proof[i] ^ clientSignature[i]
	}
	if !hmac.Equal(s.hash(recoveredKey), storedKey) {
		errReply := newDoc().addDouble("ok", 0).addString("errmsg", "Authentication failed.").bytes()
		return s.writeReply(errReply, requestID)
	}

	serverKey := s.hmac(saltedPassword, "Server Key")
	serverSig := s.hmac(serverKey, authMessage)
	finalPayload := "v=" + base64.StdEncoding.EncodeToString(serverSig)
	finalReply := newDoc().
		addInt32("conversationId", 7).
		addBool("done", true).
		addBinary("payload", []byte(finalPayload)).
		addDouble("ok", 1).
		bytes()
	return s.writeReply(finalReply, requestID)
}

func (s *fakeMongoSCRAMServer) writeReply(body []byte, responseTo int32) error {
	if _, err := s.rw.Writer.Write(opMsgReplyMessage(body, responseTo)); err != nil {
		return err
	}
	return s.rw.Writer.Flush()
}

func (s *fakeMongoSCRAMServer) hash(b []byte) []byte {
	h := s.newHash()
	h.Write(b)
	return h.Sum(nil)
}

func (s *fakeMongoSCRAMServer) hmac(key []byte, msg string) []byte {
	h := hmac.New(s.newHash, key)
	h.Write([]byte(msg))
	return h.Sum(nil)
}

// pbkdf2ForTest mirrors internal/wire/scram's pbkdf2 (unexported there) so this fake server
// fixture doesn't need to import scram's internals.
func pbkdf2ForTest(newHash func() hash.Hash, password, salt []byte, iter, keyLen int) []byte {
	hLen := newHash().Size()
	numBlocks := (keyLen + hLen - 1) / hLen
	out := make([]byte, 0, numBlocks*hLen)
	var block [4]byte
	hm := func(key, msg []byte) []byte {
		h := hmac.New(newHash, key)
		h.Write(msg)
		return h.Sum(nil)
	}
	for i := 1; i <= numBlocks; i++ {
		block[0] = byte(i >> 24)
		block[1] = byte(i >> 16)
		block[2] = byte(i >> 8)
		block[3] = byte(i)
		u := hm(password, append(append([]byte{}, salt...), block[:]...))
		t := make([]byte, len(u))
		copy(t, u)
		for j := 1; j < iter; j++ {
			u = hm(password, u)
			for k := range t {
				t[k] ^= u[k]
			}
		}
		out = append(out, t...)
	}
	return out[:keyLen]
}

func TestAuthenticateUpstream_SHA256Succeeds(t *testing.T) {
	agentConn, serverConn := net.Pipe()
	defer agentConn.Close()
	defer serverConn.Close()
	dl := deadlineFor(t)
	_ = agentConn.SetDeadline(dl)
	_ = serverConn.SetDeadline(dl)

	fake := newFakeMongoSCRAMServer(t, serverConn, "alice", "correct-password", "SCRAM-SHA-256")
	serveErr := make(chan error, 1)
	go func() { serveErr <- fake.serve() }()

	upstream := bufio.NewReadWriter(bufio.NewReader(agentConn), bufio.NewWriter(agentConn))
	err := authenticateUpstream(upstream, wire.UpstreamCredential{Username: "alice", Password: "correct-password", Database: "admin"})
	if err != nil {
		t.Fatalf("authenticateUpstream: %v", err)
	}
	if err := <-serveErr; err != nil {
		t.Fatalf("fake server: %v", err)
	}
}

func TestAuthenticateUpstream_FallsBackToSHA1WhenSHA256Unavailable(t *testing.T) {
	agentConn, serverConn := net.Pipe()
	defer agentConn.Close()
	defer serverConn.Close()
	dl := deadlineFor(t)
	_ = agentConn.SetDeadline(dl)
	_ = serverConn.SetDeadline(dl)

	// Only SHA-1 is available for this user -- exercises the MechanismUnavailable fallback.
	fake := newFakeMongoSCRAMServer(t, serverConn, "bob", "legacy-password", "SCRAM-SHA-1")
	serveErr := make(chan error, 1)
	go func() {
		// First conversation attempt (SHA-256) fails fast at saslStart; serve a second time for
		// the SHA-1 retry.
		if err := fake.serve(); err != nil {
			serveErr <- err
			return
		}
		serveErr <- fake.serve()
	}()

	upstream := bufio.NewReadWriter(bufio.NewReader(agentConn), bufio.NewWriter(agentConn))
	err := authenticateUpstream(upstream, wire.UpstreamCredential{Username: "bob", Password: "legacy-password", Database: "admin"})
	if err != nil {
		t.Fatalf("authenticateUpstream: %v", err)
	}
	if err := <-serveErr; err != nil {
		t.Fatalf("fake server: %v", err)
	}
}

func TestAuthenticateUpstream_WrongPasswordFails(t *testing.T) {
	agentConn, serverConn := net.Pipe()
	defer agentConn.Close()
	defer serverConn.Close()
	dl := deadlineFor(t)
	_ = agentConn.SetDeadline(dl)
	_ = serverConn.SetDeadline(dl)

	fake := newFakeMongoSCRAMServer(t, serverConn, "alice", "correct-password", "SCRAM-SHA-256")
	serveErr := make(chan error, 1)
	go func() { serveErr <- fake.serve() }()

	upstream := bufio.NewReadWriter(bufio.NewReader(agentConn), bufio.NewWriter(agentConn))
	err := authenticateUpstream(upstream, wire.UpstreamCredential{Username: "alice", Password: "wrong-password", Database: "admin"})
	if err == nil {
		t.Fatal("expected authenticateUpstream to fail with a wrong password")
	}
	<-serveErr
}
