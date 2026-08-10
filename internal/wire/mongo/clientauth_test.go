package mongo

import (
	"bufio"
	"net"
	"testing"
	"time"
)

// clientHelloCommand builds a client's hello command (OP_MSG, requestID set) with the given
// authSource ($db).
func clientHelloCommand(authDB string, requestID int32) []byte {
	body := newDoc().addInt32("hello", 1).addString("$db", authDB).bytes()
	return opMsgRequest(body, requestID)
}

// clientSaslStartPlain builds a client's saslStart(PLAIN) command presenting authcid/password as
// the RFC 4616 PLAIN payload (empty authzid).
func clientSaslStartPlain(authDB, authcid, password string, requestID int32) []byte {
	payload := []byte("\x00" + authcid + "\x00" + password)
	body := newDoc().
		addInt32("saslStart", 1).
		addString("mechanism", saslMechanismPlain).
		addBinary("payload", payload).
		addBool("autoAuthorize", true).
		addString("$db", authDB).
		bytes()
	return opMsgRequest(body, requestID)
}

// clientSaslStartOtherMechanism builds a saslStart requesting a mechanism other than PLAIN, to
// exercise the "client didn't ask for PLAIN" error path.
func clientSaslStartOtherMechanism(mechanism, authDB string, requestID int32) []byte {
	body := newDoc().
		addInt32("saslStart", 1).
		addString("mechanism", mechanism).
		addBinary("payload", []byte("n,,n=,r=fakenonce")).
		addString("$db", authDB).
		bytes()
	return opMsgRequest(body, requestID)
}

func pipePair(t *testing.T) (client, server net.Conn) {
	t.Helper()
	c, s := net.Pipe()
	dl := time.Now().Add(5 * time.Second)
	_ = c.SetDeadline(dl)
	_ = s.SetDeadline(dl)
	return c, s
}

func TestTerminateClientAuth_FullPlainHandshake(t *testing.T) {
	client, server := pipePair(t)
	defer client.Close()
	defer server.Close()

	serverRW := bufio.NewReadWriter(bufio.NewReader(server), bufio.NewWriter(server))
	result := make(chan struct {
		secret  string
		startup map[string]string
		err     error
	}, 1)
	go func() {
		secret, startup, requestID, err := terminateClientAuth(serverRW)
		if err == nil {
			// Simulates ProxyInject sending the deferred OK only after upstream auth would have
			// succeeded (here, immediately, since this test only exercises terminateClientAuth).
			err = sendClientAuthOK(serverRW, requestID)
		}
		result <- struct {
			secret  string
			startup map[string]string
			err     error
		}{secret, startup, err}
	}()

	clientR := bufio.NewReader(client)

	// Client sends hello.
	if _, err := client.Write(clientHelloCommand("admin", 1)); err != nil {
		t.Fatalf("write hello: %v", err)
	}
	helloReplyMsg, err := readMessage(clientR)
	if err != nil {
		t.Fatalf("read hello reply: %v", err)
	}
	helloDoc, ok := parseCommandDocGeneric(helloReplyMsg)
	if !ok {
		t.Fatal("could not parse hello reply")
	}
	if stringField(helloDoc, "ismaster") != "" {
		// ismaster is bool, not string -- just confirm the doc parsed with an "ok" field.
	}
	if _, hasOk := helloDoc["ok"]; !hasOk {
		t.Fatal("hello reply missing ok field")
	}

	// Client sends saslStart(PLAIN) with the session token as password.
	if _, err := client.Write(clientSaslStartPlain("admin", "actor@example.com", "proxy-session-token", 2)); err != nil {
		t.Fatalf("write saslStart: %v", err)
	}
	saslReplyMsg, err := readMessage(clientR)
	if err != nil {
		t.Fatalf("read saslStart reply: %v", err)
	}
	saslReplyDoc, ok := parseCommandDocGeneric(saslReplyMsg)
	if !ok {
		t.Fatal("could not parse saslStart reply")
	}
	if _, hasDone := saslReplyDoc["done"]; !hasDone {
		t.Fatal("saslStart reply missing done field")
	}

	r := <-result
	if r.err != nil {
		t.Fatalf("terminateClientAuth: %v", r.err)
	}
	if r.secret != "proxy-session-token" {
		t.Fatalf("secret = %q, want proxy-session-token", r.secret)
	}
	if r.startup["user"] != "actor@example.com" {
		t.Fatalf("startup[user] = %q, want actor@example.com", r.startup["user"])
	}
	if r.startup["database"] != "admin" {
		t.Fatalf("startup[database] = %q, want admin", r.startup["database"])
	}
}

func TestTerminateClientAuth_RejectsNonPlainMechanism(t *testing.T) {
	client, server := pipePair(t)
	defer client.Close()
	defer server.Close()

	serverRW := bufio.NewReadWriter(bufio.NewReader(server), bufio.NewWriter(server))
	errc := make(chan error, 1)
	go func() {
		_, _, _, err := terminateClientAuth(serverRW)
		errc <- err
	}()

	clientR := bufio.NewReader(client)
	if _, err := client.Write(clientHelloCommand("admin", 1)); err != nil {
		t.Fatalf("write hello: %v", err)
	}
	if _, err := readMessage(clientR); err != nil {
		t.Fatalf("read hello reply: %v", err)
	}
	if _, err := client.Write(clientSaslStartOtherMechanism("SCRAM-SHA-256", "admin", 2)); err != nil {
		t.Fatalf("write saslStart: %v", err)
	}

	err := <-errc
	if err == nil {
		t.Fatal("expected an error when the client requests a non-PLAIN mechanism")
	}
}

func TestTerminateClientAuth_RejectsLegacyOpQuery(t *testing.T) {
	client, server := pipePair(t)
	defer client.Close()
	defer server.Close()

	serverRW := bufio.NewReadWriter(bufio.NewReader(server), bufio.NewWriter(server))
	errc := make(chan error, 1)
	go func() {
		_, _, _, err := terminateClientAuth(serverRW)
		errc <- err
	}()

	// A legacy OP_QUERY message: header with opcode 2004, arbitrary body.
	msg := make([]byte, headerLen+4)
	msg[12], msg[13], msg[14], msg[15] = 0xd4, 0x07, 0x00, 0x00 // 2004 little-endian
	msg[0] = byte(len(msg))
	if _, err := client.Write(msg); err != nil {
		t.Fatalf("write legacy op_query: %v", err)
	}

	err := <-errc
	if err != errLegacyHandshakeUnsupported {
		t.Fatalf("expected errLegacyHandshakeUnsupported, got %v", err)
	}
}

func TestDecodePlainPayload(t *testing.T) {
	authzid, authcid, password, err := decodePlainPayload([]byte("\x00alice\x00secret"))
	if err != nil {
		t.Fatalf("decodePlainPayload: %v", err)
	}
	if authzid != "" || authcid != "alice" || password != "secret" {
		t.Fatalf("got (%q, %q, %q)", authzid, authcid, password)
	}
}

func TestDecodePlainPayload_Malformed(t *testing.T) {
	if _, _, _, err := decodePlainPayload([]byte("no-nul-separators")); err == nil {
		t.Fatal("expected an error for a malformed PLAIN payload")
	}
}
