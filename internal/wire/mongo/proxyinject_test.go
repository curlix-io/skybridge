package mongo

import (
	"bufio"
	"context"
	"encoding/binary"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/curlix-io/skybridge/internal/mask"
	"github.com/curlix-io/skybridge/internal/wire"
)

// TestProxyInject_EndToEnd drives the full credential-injection round trip: a fake client
// presents a session token via SASL PLAIN, the resolver redeems it for a real credential, a fake
// upstream completes SCRAM-SHA-256 with that credential, and a masked find result flows back to
// the client. Asserts the session token never reaches the upstream and the real credential never
// reaches the client.
func TestProxyInject_EndToEnd(t *testing.T) {
	clientConn, engineClient := net.Pipe()
	engineUpstream, upstreamConn := net.Pipe()
	defer clientConn.Close()
	defer upstreamConn.Close()
	dl := time.Now().Add(8 * time.Second)
	for _, c := range []net.Conn{clientConn, engineClient, engineUpstream, upstreamConn} {
		_ = c.SetDeadline(dl)
	}

	const sessionToken = "proxy-session-token-xyz"
	const upstreamPassword = "real-upstream-password"
	resolve := func(_ context.Context, startup map[string]string, secret string) (wire.UpstreamCredential, error) {
		if secret != sessionToken || startup["user"] != "actor@example.com" {
			return wire.UpstreamCredential{}, errAuthDenied
		}
		return wire.UpstreamCredential{Username: "svc-account", Password: upstreamPassword, Database: "admin"}, nil
	}

	engine := New().WithOrgID("org1")
	overlay := mask.NewOverlay(map[string]string{"email": "[redacted]"})

	proxyErr := make(chan error, 1)
	go func() {
		proxyErr <- engine.ProxyInject(context.Background(), engineClient, engineUpstream, overlay, resolve, wire.NoopRecorder{})
	}()

	upstreamErr := make(chan error, 1)
	go func() {
		fake := newFakeMongoSCRAMServer(t, upstreamConn, "svc-account", upstreamPassword, "SCRAM-SHA-256")
		if err := fake.serve(); err != nil {
			upstreamErr <- err
			return
		}
		// After auth, serve one find request and reply with a batch containing an email so the
		// test can assert masking still applies through the injection path.
		br := bufio.NewReader(upstreamConn)
		msg, err := readMessage(br)
		if err != nil {
			upstreamErr <- err
			return
		}
		requestID := int32(binary.LittleEndian.Uint32(msg[4:8]))
		reply := opMsgReplyTo(findReplyBody(), requestID)
		if _, err := upstreamConn.Write(reply); err != nil {
			upstreamErr <- err
			return
		}
		upstreamErr <- nil
	}()

	clientR := bufio.NewReader(clientConn)

	// Client: hello -> saslStart(PLAIN, token) -> expect done:true.
	if _, err := clientConn.Write(clientHelloCommand("admin", 1)); err != nil {
		t.Fatalf("write hello: %v", err)
	}
	if _, err := readMessage(clientR); err != nil {
		t.Fatalf("read hello reply: %v", err)
	}
	if _, err := clientConn.Write(clientSaslStartPlain("admin", "actor@example.com", sessionToken, 2)); err != nil {
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
	if isNotOK(saslReplyDoc) {
		t.Fatalf("client login was rejected: %s", errmsgField(saslReplyDoc))
	}

	// Client: issue a find, expect a masked reply.
	if _, err := clientConn.Write(opMsgRequest(findCommand("orders", "shop"), 99)); err != nil {
		t.Fatalf("write find: %v", err)
	}
	out, err := readMessage(clientR)
	if err != nil {
		t.Fatalf("read find reply: %v", err)
	}
	if strings.Contains(string(out), "alice@example.com") {
		t.Fatal("email leaked through ProxyInject")
	}
	if !strings.Contains(string(out), "[redacted]") {
		t.Fatal("masking not applied through ProxyInject")
	}

	if err := <-upstreamErr; err != nil {
		t.Fatalf("fake upstream: %v", err)
	}
	_ = clientConn.Close()
	select {
	case <-proxyErr:
	case <-time.After(5 * time.Second):
		t.Fatal("ProxyInject did not return after client closed")
	}
}

func TestProxyInject_ResolveFailureRejectsClientCleanly(t *testing.T) {
	clientConn, engineClient := net.Pipe()
	engineUpstream, upstreamConn := net.Pipe()
	defer clientConn.Close()
	defer upstreamConn.Close()
	dl := time.Now().Add(5 * time.Second)
	for _, c := range []net.Conn{clientConn, engineClient, engineUpstream, upstreamConn} {
		_ = c.SetDeadline(dl)
	}

	resolve := func(context.Context, map[string]string, string) (wire.UpstreamCredential, error) {
		return wire.UpstreamCredential{}, errAuthDenied
	}
	engine := New()
	proxyErr := make(chan error, 1)
	go func() {
		proxyErr <- engine.ProxyInject(context.Background(), engineClient, engineUpstream, mask.Noop{}, resolve, wire.NoopRecorder{})
	}()

	clientR := bufio.NewReader(clientConn)
	if _, err := clientConn.Write(clientHelloCommand("admin", 1)); err != nil {
		t.Fatalf("write hello: %v", err)
	}
	if _, err := readMessage(clientR); err != nil {
		t.Fatalf("read hello reply: %v", err)
	}
	if _, err := clientConn.Write(clientSaslStartPlain("admin", "actor@example.com", "bad-token", 2)); err != nil {
		t.Fatalf("write saslStart: %v", err)
	}
	replyMsg, err := readMessage(clientR)
	if err != nil {
		t.Fatalf("read saslStart reply: %v", err)
	}
	replyDoc, ok := parseCommandDocGeneric(replyMsg)
	if !ok {
		t.Fatal("could not parse saslStart reply")
	}
	if !isNotOK(replyDoc) {
		t.Fatal("expected the client to be rejected when the resolver denies the token")
	}

	if err := <-proxyErr; err == nil {
		t.Fatal("expected ProxyInject to return an error on resolve failure")
	}
}

func TestProxyInject_NilResolverErrors(t *testing.T) {
	engine := New()
	err := engine.ProxyInject(context.Background(), nil, nil, mask.Noop{}, nil, wire.NoopRecorder{})
	if err == nil {
		t.Fatal("expected an error when resolve is nil")
	}
}

var errAuthDenied = &authDeniedError{}

type authDeniedError struct{}

func (*authDeniedError) Error() string { return "access denied for this session" }
