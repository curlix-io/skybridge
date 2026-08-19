package gateway

import (
	"context"
	"io"
	"log/slog"
	"net"
	"testing"
	"time"

	"github.com/curlix-io/skybridge/internal/tunnel"
)

func silentLogger() *slog.Logger { return slog.New(slog.NewTextHandler(io.Discard, nil)) }

// funcResolver adapts a function to TargetResolver for tests that need a specific canned response.
type funcResolver func(ctx context.Context, orgID, target string) (tunnel.Target, error)

func (f funcResolver) Resolve(ctx context.Context, orgID, target string) (tunnel.Target, error) {
	return f(ctx, orgID, target)
}

// funcWireAdmitter adapts a function to WireAdmitter for tests.
type funcWireAdmitter func(ctx context.Context, orgID, clientIP, target string) error

func (f funcWireAdmitter) Admit(ctx context.Context, orgID, clientIP, target string) error {
	return f(ctx, orgID, clientIP, target)
}

// funcAgentAuthVerifier adapts a function to AgentAuthVerifier for tests that need a specific
// canned response, without standing up an HTTP control plane.
type funcAgentAuthVerifier func(ctx context.Context, token string) (tenantID, agentID string, ok bool)

func (f funcAgentAuthVerifier) Verify(ctx context.Context, token string) (string, string, bool) {
	return f(ctx, token)
}

func TestNew_DefaultsLoggerWhenNil(t *testing.T) {
	g := New(nil)
	if g.log == nil {
		t.Fatal("expected New to default a nil logger rather than leave it nil")
	}
	if _, ok := g.store.(NoopStore); !ok {
		t.Fatalf("expected default store to be NoopStore, got %T", g.store)
	}
	if _, ok := g.admitter.(NoopWireAdmitter); !ok {
		t.Fatalf("expected default admitter to be NoopWireAdmitter, got %T", g.admitter)
	}
	if _, ok := g.resolver.(NoopTargetResolver); !ok {
		t.Fatalf("expected default resolver to be NoopTargetResolver, got %T", g.resolver)
	}
	if _, ok := g.connLimiter.(NoopConnRateLimiter); !ok {
		t.Fatalf("expected default conn limiter to be NoopConnRateLimiter, got %T", g.connLimiter)
	}
}

func TestSetStore_NilDefaultsToNoop(t *testing.T) {
	g := New(silentLogger())
	g.SetStore(nil)
	if _, ok := g.store.(NoopStore); !ok {
		t.Fatalf("expected SetStore(nil) to install NoopStore, got %T", g.store)
	}
}

func TestSetTargetResolver_NilDefaultsToNoop(t *testing.T) {
	g := New(silentLogger())
	g.SetTargetResolver(nil)
	if _, ok := g.resolver.(NoopTargetResolver); !ok {
		t.Fatalf("expected SetTargetResolver(nil) to install NoopTargetResolver, got %T", g.resolver)
	}
}

func TestSetConnRateLimiter_NilDefaultsToNoop(t *testing.T) {
	g := New(silentLogger())
	g.SetConnRateLimiter(nil)
	if _, ok := g.connLimiter.(NoopConnRateLimiter); !ok {
		t.Fatalf("expected SetConnRateLimiter(nil) to install NoopConnRateLimiter, got %T", g.connLimiter)
	}
}

func TestSetWireAdmitter(t *testing.T) {
	g := New(silentLogger())
	g.SetWireAdmitter(nil)
	if _, ok := g.admitter.(NoopWireAdmitter); !ok {
		t.Fatalf("expected SetWireAdmitter(nil) to install NoopWireAdmitter, got %T", g.admitter)
	}
	called := false
	g.SetWireAdmitter(funcWireAdmitter(func(context.Context, string, string, string) error {
		called = true
		return nil
	}))
	_ = g.admitter.Admit(context.Background(), "org", "1.2.3.4", "db")
	if !called {
		t.Fatal("expected the installed admitter to be used")
	}
}

func TestSetRequireOrgID(t *testing.T) {
	g := New(silentLogger())
	if g.requireOrgID {
		t.Fatal("expected requireOrgID to default false")
	}
	g.SetRequireOrgID(true)
	if !g.requireOrgID {
		t.Fatal("expected SetRequireOrgID(true) to set the field")
	}
}

func TestHandleTranscript_EmptySessionIDNoops(t *testing.T) {
	g := New(silentLogger())
	called := false
	g.SetStore(&transcriptStore{onTranscript: func(string, TranscriptChunks) error {
		called = true
		return nil
	}})
	g.handleTranscript(&agentConn{orgID: "org1"}, tunnel.Control{Kind: tunnel.KindTranscript, SessionID: ""})
	if called {
		t.Fatal("expected an empty session id to skip the store call")
	}
}

func TestHandleTranscript_ForwardsToStore(t *testing.T) {
	g := New(silentLogger())
	var gotID string
	var gotChunks TranscriptChunks
	g.SetStore(&transcriptStore{onTranscript: func(id string, c TranscriptChunks) error {
		gotID = id
		gotChunks = c
		return nil
	}})
	g.handleTranscript(&agentConn{orgID: "org1"}, tunnel.Control{
		Kind:             tunnel.KindTranscript,
		SessionID:        "sess-1",
		TranscriptChunks: []tunnel.TranscriptChunk{{Seq: 1, Direction: "input", Text: "hi", Bytes: 2}},
		Truncated:        true,
	})
	if gotID != "sess-1" {
		t.Fatalf("session id = %q", gotID)
	}
	if gotChunks.OrgID != "org1" || !gotChunks.Truncated || len(gotChunks.Chunks) != 1 {
		t.Fatalf("chunks = %+v", gotChunks)
	}
}

func TestHandleTranscript_StoreErrorDoesNotPanic(t *testing.T) {
	g := New(silentLogger())
	g.SetStore(&transcriptStore{onTranscript: func(string, TranscriptChunks) error {
		return errBoom
	}})
	// Must not panic; error is only logged (best-effort).
	g.handleTranscript(&agentConn{orgID: "org1"}, tunnel.Control{Kind: tunnel.KindTranscript, SessionID: "sess-1"})
}

type transcriptStore struct {
	onTranscript func(string, TranscriptChunks) error
}

func (transcriptStore) SessionStarted(context.Context, SessionRecord) (string, error) { return "", nil }
func (transcriptStore) SessionEnded(context.Context, string, SessionResult) error     { return nil }
func (s *transcriptStore) SessionTranscript(_ context.Context, id string, c TranscriptChunks) error {
	return s.onTranscript(id, c)
}

var errBoom = &testError{"boom"}

type testError struct{ msg string }

func (e *testError) Error() string { return e.msg }

func TestOpen_ResolvesAndOpensStreamOverAgentTunnel(t *testing.T) {
	g := New(silentLogger())
	g.SetTargetResolver(funcResolver(func(_ context.Context, orgID, target string) (tunnel.Target, error) {
		if orgID != "org1" || target != "db" {
			t.Fatalf("unexpected resolve args org=%q target=%q", orgID, target)
		}
		return tunnel.Target{Addr: "upstream:5432", DBType: "postgres", ResourceRoleID: "role-1"}, nil
	}))

	agentSide, gwSide := net.Pipe()
	defer agentSide.Close()
	defer gwSide.Close()
	gwSess := tunnel.Server(gwSide)
	agentSess := tunnel.Client(agentSide)

	acceptDone := make(chan tunnel.OpenMeta, 1)
	go func() {
		st, err := agentSess.Accept()
		if err != nil {
			return
		}
		meta, _ := tunnel.DecodeOpenMeta(st.Meta())
		acceptDone <- meta
		buf := make([]byte, 4)
		_, _ = st.Read(buf)
		_, _ = st.Write([]byte("pong"))
	}()

	g.register(&agentConn{id: "a1", orgID: "org1", sess: gwSess})

	stream, err := g.Open(context.Background(), "org1", "db")
	if err != nil {
		t.Fatal(err)
	}
	defer stream.Close()

	select {
	case meta := <-acceptDone:
		if meta.Addr != "upstream:5432" || meta.DBType != "postgres" || meta.ResourceRoleID != "role-1" {
			t.Fatalf("unexpected open meta: %+v", meta)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("agent side never saw the opened stream")
	}

	if _, err := stream.Write([]byte("ping")); err != nil {
		t.Fatal(err)
	}
	got := make([]byte, 4)
	_ = stream.SetReadDeadline(time.Now().Add(2 * time.Second))
	if _, err := io.ReadFull(stream, got); err != nil {
		t.Fatal(err)
	}
	if string(got) != "pong" {
		t.Fatalf("got %q want pong", got)
	}
}

func TestOpen_NoAgentForOrg(t *testing.T) {
	g := New(silentLogger())
	if _, err := g.Open(context.Background(), "org-missing", "db"); err != ErrNoAgent {
		t.Fatalf("want ErrNoAgent, got %v", err)
	}
}

func TestOpen_ResolverErrorPropagates(t *testing.T) {
	g := New(silentLogger())
	wantErr := &testError{"resolve failed"}
	g.SetTargetResolver(funcResolver(func(context.Context, string, string) (tunnel.Target, error) {
		return tunnel.Target{}, wantErr
	}))
	_, gwSide := net.Pipe()
	defer gwSide.Close()
	g.register(&agentConn{id: "a1", orgID: "org1", sess: tunnel.Server(gwSide)})

	if _, err := g.Open(context.Background(), "org1", "db"); err != wantErr {
		t.Fatalf("want %v, got %v", wantErr, err)
	}
}

// TestListenAgents_RejectsPlainTCPAndStopsOnCancel: agent registration requires a verified mTLS
// client certificate unconditionally (no bearer-token fallback) — a plain TCP connection (this
// listener, unlike cmd/skybridge/gateway.go's real one, isn't TLS-wrapped) must be rejected, and
// ListenAgents must still stop cleanly on ctx cancellation afterward.
func TestListenAgents_RejectsPlainTCPAndStopsOnCancel(t *testing.T) {
	g := New(silentLogger())
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	errc := make(chan error, 1)
	go func() { errc <- g.ListenAgents(ctx, ln) }()

	conn, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	sess := tunnel.Client(conn)
	if err := sess.SendControl(tunnel.Control{Kind: tunnel.KindRegister, AgentID: "a1", OrgID: "org1"}); err != nil {
		t.Fatal(err)
	}
	ack, err := sess.NextControl()
	if err != nil {
		t.Fatal(err)
	}
	if ack.OK {
		t.Fatalf("expected registration without a verified mTLS client cert to be rejected, got %+v", ack)
	}

	if waitForOrgAgentInternal(g, "org1", 200*time.Millisecond) {
		t.Fatal("rejected connection must not be registered as org1's agent")
	}

	cancel()
	select {
	case err := <-errc:
		if err != nil {
			t.Fatalf("expected ListenAgents to return nil on ctx cancellation, got %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("ListenAgents did not stop after ctx cancellation")
	}
}

func TestListenClients_AcceptsAndStopsOnCancel(t *testing.T) {
	g := New(silentLogger())
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	errc := make(chan error, 1)
	go func() { errc <- g.ListenClients(ctx, ln, "org1", "db") }()

	conn, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	// No agent registered for org1, so ServeClient rejects and closes the connection quickly.
	buf := make([]byte, 1)
	_ = conn.SetReadDeadline(time.Now().Add(2 * time.Second))
	if _, err := conn.Read(buf); err == nil {
		t.Fatal("expected the rejected client connection to be closed")
	}
	conn.Close()

	cancel()
	select {
	case err := <-errc:
		if err != nil {
			t.Fatalf("expected ListenClients to return nil on ctx cancellation, got %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("ListenClients did not stop after ctx cancellation")
	}
}

func waitForOrgAgentInternal(g *Gateway, orgID string, d time.Duration) bool {
	deadline := time.Now().Add(d)
	for time.Now().Before(deadline) {
		for _, o := range g.RegisteredOrgs() {
			if o == orgID {
				return true
			}
		}
		time.Sleep(5 * time.Millisecond)
	}
	return false
}

func TestServeAgent_RejectsNonRegisterFirstControl(t *testing.T) {
	g := New(silentLogger())
	gw, local := net.Pipe()
	defer local.Close()

	errc := make(chan error, 1)
	go func() { errc <- g.ServeAgent(gw) }()

	sess := tunnel.Client(local)
	if err := sess.SendControl(tunnel.Control{Kind: tunnel.KindHeartbeat}); err != nil {
		t.Fatal(err)
	}
	select {
	case err := <-errc:
		if err == nil {
			t.Fatal("expected ServeAgent to reject a non-register first control message")
		}
	case <-time.After(2 * time.Second):
		t.Fatal("ServeAgent did not return in time")
	}
}

func TestServeAgent_RejectsMissingAgentID(t *testing.T) {
	g := New(silentLogger())
	gw, local := net.Pipe()
	defer local.Close()

	errc := make(chan error, 1)
	go func() { errc <- g.ServeAgent(gw) }()

	sess := tunnel.Client(local)
	if err := sess.SendControl(tunnel.Control{Kind: tunnel.KindRegister}); err != nil {
		t.Fatal(err)
	}
	select {
	case err := <-errc:
		if err == nil {
			t.Fatal("expected ServeAgent to reject a registration with no agent_id")
		}
	case <-time.After(2 * time.Second):
		t.Fatal("ServeAgent did not return in time")
	}
}

// TestServeAgent_NoMTLSNoVerifierInstalledRejectsBearerToken is a regression guard for the
// default-fails-closed contract: without SetAgentAuthVerifier, a connection with no verified mTLS
// client cert must still be rejected even if it presents a Token — NoopAgentAuthVerifier must
// never accept anything.
func TestServeAgent_NoMTLSNoVerifierInstalledRejectsBearerToken(t *testing.T) {
	g := New(silentLogger())
	gw, local := net.Pipe()
	defer local.Close()

	errc := make(chan error, 1)
	go func() { errc <- g.ServeAgent(gw) }()

	sess := tunnel.Client(local)
	if err := sess.SendControl(tunnel.Control{Kind: tunnel.KindRegister, AgentID: "a1", OrgID: "org1", Token: "some-token"}); err != nil {
		t.Fatal(err)
	}
	ack, err := sess.NextControl()
	if err != nil {
		t.Fatal(err)
	}
	if ack.OK {
		t.Fatal("expected registration to be rejected with no mTLS cert and no verifier installed")
	}
	<-errc
}

// TestServeAgent_BearerFallbackAcceptsValidToken is the actual reusable-connector-key path: no
// mTLS client cert, but a verifier that recognizes the presented Token.
func TestServeAgent_BearerFallbackAcceptsValidToken(t *testing.T) {
	g := New(silentLogger())
	g.SetAgentAuthVerifier(funcAgentAuthVerifier(func(_ context.Context, token string) (string, string, bool) {
		if token != "good-token" {
			return "", "", false
		}
		return "org1", "a1", true
	}))
	gw, local := net.Pipe()
	defer local.Close()

	errc := make(chan error, 1)
	go func() { errc <- g.ServeAgent(gw) }()

	sess := tunnel.Client(local)
	if err := sess.SendControl(tunnel.Control{Kind: tunnel.KindRegister, AgentID: "a1", OrgID: "org1", Token: "good-token"}); err != nil {
		t.Fatal(err)
	}
	ack, err := sess.NextControl()
	if err != nil {
		t.Fatal(err)
	}
	if !ack.OK {
		t.Fatalf("expected registration to succeed via bearer fallback, got error: %s", ack.Error)
	}
	local.Close()
	<-errc
}

// TestServeAgent_BearerFallbackRejectsInvalidToken confirms an unrecognized token is rejected the
// same way a missing/invalid mTLS cert is — not silently treated as anonymous/unscoped.
func TestServeAgent_BearerFallbackRejectsInvalidToken(t *testing.T) {
	g := New(silentLogger())
	g.SetAgentAuthVerifier(funcAgentAuthVerifier(func(context.Context, string) (string, string, bool) {
		return "", "", false
	}))
	gw, local := net.Pipe()
	defer local.Close()

	errc := make(chan error, 1)
	go func() { errc <- g.ServeAgent(gw) }()

	sess := tunnel.Client(local)
	if err := sess.SendControl(tunnel.Control{Kind: tunnel.KindRegister, AgentID: "a1", OrgID: "org1", Token: "bad-token"}); err != nil {
		t.Fatal(err)
	}
	ack, err := sess.NextControl()
	if err != nil {
		t.Fatal(err)
	}
	if ack.OK {
		t.Fatal("expected registration to be rejected for an unrecognized bearer token")
	}
	<-errc
}

// TestServeAgent_BearerFallbackOrgIDMismatchRejected mirrors the mTLS-cert org_id-mismatch check
// (gateway.go's mtlsVerified branch) — a caller can't claim a different org_id than the token it
// presents is actually bound to.
func TestServeAgent_BearerFallbackOrgIDMismatchRejected(t *testing.T) {
	g := New(silentLogger())
	g.SetAgentAuthVerifier(funcAgentAuthVerifier(func(context.Context, string) (string, string, bool) {
		return "org1", "a1", true
	}))
	gw, local := net.Pipe()
	defer local.Close()

	errc := make(chan error, 1)
	go func() { errc <- g.ServeAgent(gw) }()

	sess := tunnel.Client(local)
	if err := sess.SendControl(tunnel.Control{Kind: tunnel.KindRegister, AgentID: "a1", OrgID: "org2", Token: "good-token"}); err != nil {
		t.Fatal(err)
	}
	ack, err := sess.NextControl()
	if err != nil {
		t.Fatal(err)
	}
	if ack.OK {
		t.Fatal("expected registration to be rejected when claimed org_id does not match the bearer token's bound org")
	}
	<-errc
}

func TestListenClients_AcceptErrorPropagatesWhenCtxNotCancelled(t *testing.T) {
	g := New(silentLogger())
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	errc := make(chan error, 1)
	go func() { errc <- g.ListenClients(context.Background(), ln, "org1", "db") }()

	// Closing the listener directly (without cancelling ctx) makes the next Accept fail with
	// ctx.Err() == nil, so ListenClients must propagate that error rather than swallow it.
	time.Sleep(20 * time.Millisecond)
	ln.Close()

	select {
	case err := <-errc:
		if err == nil {
			t.Fatal("expected ListenClients to propagate the Accept error")
		}
	case <-time.After(2 * time.Second):
		t.Fatal("ListenClients did not return after the listener was closed")
	}
}

func TestServeClient_AdmitterRejects(t *testing.T) {
	g := New(silentLogger())
	wantErr := &testError{"denied"}
	g.SetWireAdmitter(funcWireAdmitter(func(context.Context, string, string, string) error {
		return wantErr
	}))
	g.SetTargetResolver(funcResolver(func(context.Context, string, string) (tunnel.Target, error) {
		t.Fatal("resolver should not be reached when the admitter rejects the client")
		return tunnel.Target{}, nil
	}))

	agentSide, gwSide := net.Pipe()
	defer agentSide.Close()
	gwSess := tunnel.Server(gwSide)
	g.register(&agentConn{id: "a1", orgID: "org1", sess: gwSess})

	clientGW, client := net.Pipe()
	defer client.Close()
	err := g.ServeClient(clientGW, "org1", "db")
	if err != wantErr {
		t.Fatalf("want %v, got %v", wantErr, err)
	}
}

func TestServeClient_StoreStartedErrorIsBestEffort(t *testing.T) {
	g := New(silentLogger())

	failing := &failingStartStore{}
	g.SetStore(failing)
	g.SetTargetResolver(funcResolver(func(context.Context, string, string) (tunnel.Target, error) {
		return tunnel.Target{Addr: "upstream:0", DBType: "postgres"}, nil
	}))

	agentSide, gwSide := net.Pipe()
	defer agentSide.Close()
	gwSess := tunnel.Server(gwSide)
	agentSess := tunnel.Client(agentSide)
	g.register(&agentConn{id: "a1", orgID: "org1", sess: gwSess})

	acceptDone := make(chan struct{})
	go func() {
		st, err := agentSess.Accept()
		if err != nil {
			return
		}
		close(acceptDone)
		_, _ = io.Copy(io.Discard, st)
	}()

	clientGW, client := net.Pipe()
	relayDone := make(chan error, 1)
	go func() { relayDone <- g.ServeClient(clientGW, "org1", "db") }()

	select {
	case <-acceptDone:
	case <-time.After(2 * time.Second):
		t.Fatal("agent never saw the opened stream despite the store start failure being best-effort")
	}
	_ = client.Close()

	select {
	case <-relayDone:
	case <-time.After(2 * time.Second):
		t.Fatal("ServeClient did not return after the client closed")
	}
	if !failing.called {
		t.Fatal("expected SessionStarted to have been called despite its error")
	}
}

type failingStartStore struct {
	called bool
}

func (s *failingStartStore) SessionStarted(context.Context, SessionRecord) (string, error) {
	s.called = true
	return "", errBoom
}
func (*failingStartStore) SessionEnded(context.Context, string, SessionResult) error { return nil }
func (*failingStartStore) SessionTranscript(context.Context, string, TranscriptChunks) error {
	return nil
}

func TestTapReader_NilTapReturnsOriginal(t *testing.T) {
	r := &nopReader{}
	got := tapReader(r, nil)
	if got != io.Reader(r) {
		t.Fatal("expected tapReader(r, nil) to return r unchanged")
	}
}

type nopReader struct{}

func (nopReader) Read(p []byte) (int, error) { return 0, io.EOF }
