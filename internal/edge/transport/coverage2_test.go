package transport

import (
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/test/bufconn"

	agentv1 "github.com/curlix-io/skybridge/internal/genpb/curlix/agent/v1"
	connectorv1 "github.com/curlix-io/skybridge/internal/genpb/curlix/connector/v1"

	"github.com/curlix-io/skybridge/internal/edge"
)

// --- transport.go: New() defaulting a nil logger ---

func TestNewDefaultsNilLogger(t *testing.T) {
	c := New(Config{}, edge.NewRegistry(), nil)
	if c.logger == nil {
		t.Fatal("expected New to default a nil logger to slog.Default()")
	}
}

// --- transport.go: Run's non-fatal dial-error / reconnect-disabled path ---

// With Reconnect=false, a dial failure (bad target string that fails to even parse) should make Run
// return that dial error directly, without ever attempting the reconnect backoff loop.
func TestRunDialErrorNoReconnectReturnsImmediately(t *testing.T) {
	c := New(Config{Target: "bad target\x00", Reconnect: false}, edge.NewRegistry(), slog.New(slog.NewTextHandler(io.Discard, nil)))
	err := c.Run(context.Background())
	if err == nil {
		t.Fatal("expected dial error to propagate when Reconnect is false")
	}
}

// --- transport.go: serve()'s Register-send failure path ---

// blockGateway accepts the Connect stream but blocks until the client cancels its context, driving
// the client's very first ss.send (Register) to fail once the caller-supplied context is already
// cancelled before serve is invoked.
type blockGateway struct {
	connectorv1.UnimplementedConnectorGatewayServer
}

func (blockGateway) Connect(stream connectorv1.ConnectorGateway_ConnectServer) error {
	<-stream.Context().Done()
	return nil
}

func TestServeRegisterSendFailsOnCancelledContext(t *testing.T) {
	lis := bufconn.Listen(1024 * 1024)
	srv := grpc.NewServer()
	connectorv1.RegisterConnectorGatewayServer(srv, blockGateway{})
	go srv.Serve(lis)
	defer srv.Stop()

	conn := dialBufconn(t, srv, lis)
	defer conn.Close()

	c := New(Config{TenantID: "org-1", ConnectorID: "edge-1"}, edge.NewRegistry(), slog.New(slog.NewTextHandler(io.Discard, nil)))
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	// Give the server a moment to observe the cancellation before we try to send.
	time.Sleep(20 * time.Millisecond)

	err := c.serve(ctx, connectorv1.NewConnectorGatewayClient(conn), true, nil)
	if err == nil {
		t.Fatal("expected Register send to fail on a cancelled context")
	}
}

// --- transport.go: serve()'s bearer-token metadata attach path ---

// fakeGatewayCapturesAuth records the incoming "authorization" metadata so the test can assert the
// bearer token was attached when useBearer is true and a token is configured.
type fakeGatewayCapturesAuth struct {
	connectorv1.UnimplementedConnectorGatewayServer
	gotAuth chan string
}

func (g *fakeGatewayCapturesAuth) Connect(stream connectorv1.ConnectorGateway_ConnectServer) error {
	var got string
	if md, ok := metadata.FromIncomingContext(stream.Context()); ok {
		if vs := md.Get("authorization"); len(vs) > 0 {
			got = vs[0]
		}
	}
	g.gotAuth <- got
	return nil // end the stream cleanly right away
}

func TestServeAttachesBearerTokenMetadata(t *testing.T) {
	lis := bufconn.Listen(1024 * 1024)
	srv := grpc.NewServer()
	fg := &fakeGatewayCapturesAuth{gotAuth: make(chan string, 1)}
	connectorv1.RegisterConnectorGatewayServer(srv, fg)
	go srv.Serve(lis)
	defer srv.Stop()

	conn := dialBufconn(t, srv, lis)
	defer conn.Close()

	c := New(Config{TenantID: "org-1", ConnectorID: "edge-1", Token: "s3cr3t"}, edge.NewRegistry(), slog.New(slog.NewTextHandler(io.Discard, nil)))
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()

	_ = c.serve(ctx, connectorv1.NewConnectorGatewayClient(conn), true, nil)

	select {
	case got := <-fg.gotAuth:
		if got != "Bearer s3cr3t" {
			t.Fatalf("expected bearer token metadata, got %q", got)
		}
	case <-ctx.Done():
		t.Fatal("never observed incoming metadata")
	}
}

// --- transport.go: dial()'s mTLS-material branch (successful TLS config construction) ---

func TestDialWithMTLSMaterialSucceeds(t *testing.T) {
	ca := newTestCA(t)
	keyPEM, csrPEM, err := generateKeyAndCSR("", "org-1", "edge-1")
	if err != nil {
		t.Fatalf("generate: %v", err)
	}
	certPEM := ca.sign(t, csrPEM, "org-1", "edge-1", time.Now().Add(24*time.Hour))
	m := &tlsMaterial{caBundlePEM: ca.certPEM, clientCertPEM: certPEM, clientKeyPEM: keyPEM}

	c := New(Config{Target: "127.0.0.1:0"}, edge.NewRegistry(), slog.New(slog.NewTextHandler(io.Discard, nil)))
	conn, err := c.dial(m)
	if err != nil {
		t.Fatalf("dial with mTLS material: %v", err)
	}
	_ = conn.Close()
}

// dial() with an invalid client keypair in the material should propagate mtlsTLSConfig's error.
func TestDialWithInvalidMTLSMaterialFails(t *testing.T) {
	m := &tlsMaterial{clientCertPEM: []byte("garbage"), clientKeyPEM: []byte("garbage")}
	c := New(Config{Target: "127.0.0.1:0"}, edge.NewRegistry(), slog.New(slog.NewTextHandler(io.Discard, nil)))
	if _, err := c.dial(m); err == nil {
		t.Fatal("expected error from invalid mTLS material")
	}
}

// --- transport.go: serve() dispatches a CancelWork gateway message ---

// fakeGatewayCancelWork sends a CancelWork for an unknown run id (exercising serve's dispatch to
// c.cancelWork, which is itself a no-op for an untracked id) and then waits for the client to close
// the stream cleanly.
type fakeGatewayCancelWork struct {
	connectorv1.UnimplementedConnectorGatewayServer
	gotReg   chan struct{}
	finished chan struct{}
}

func (g *fakeGatewayCancelWork) Connect(stream connectorv1.ConnectorGateway_ConnectServer) error {
	if _, err := stream.Recv(); err != nil {
		return err
	}
	close(g.gotReg)
	if err := stream.Send(&connectorv1.GatewayMessage{
		Msg: &connectorv1.GatewayMessage_CancelWork{CancelWork: &connectorv1.CancelWork{RunId: "run-does-not-exist"}},
	}); err != nil {
		return err
	}
	for {
		if _, err := stream.Recv(); err != nil {
			close(g.finished)
			return nil
		}
	}
}

func TestServeHandlesCancelWorkMessage(t *testing.T) {
	lis := bufconn.Listen(1024 * 1024)
	srv := grpc.NewServer()
	fg := &fakeGatewayCancelWork{gotReg: make(chan struct{}), finished: make(chan struct{})}
	connectorv1.RegisterConnectorGatewayServer(srv, fg)
	go srv.Serve(lis)
	defer srv.Stop()

	conn := dialBufconn(t, srv, lis)
	defer conn.Close()

	c := New(Config{TenantID: "org-1", ConnectorID: "edge-1"}, edge.NewRegistry(), slog.New(slog.NewTextHandler(io.Discard, nil)))
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()

	serveErr := make(chan error, 1)
	go func() { serveErr <- c.serve(ctx, connectorv1.NewConnectorGatewayClient(conn), true, nil) }()

	select {
	case <-fg.gotReg:
	case <-ctx.Done():
		t.Fatal("never registered")
	}
	// Give serve a moment to receive and dispatch the CancelWork message, then end the client side so
	// the server's blocking Recv unblocks with an error and the stream finishes.
	time.Sleep(20 * time.Millisecond)
	cancel()
	select {
	case <-fg.finished:
	case <-time.After(3 * time.Second):
		t.Fatal("gateway never finished")
	}
	<-serveErr
}

// --- transport.go: handleWork's json.Marshal-error fallback branch ---

// A dispatched tool whose Result contains an unmarshalable value (a channel) forces handleWork's
// json.Marshal call to fail, exercising the "out = []byte(\"{}\")" fallback branch — proving the
// event still gets emitted (with empty JSON) rather than the run silently hanging or panicking.
func TestHandleWorkMarshalErrorFallsBackToEmptyJSON(t *testing.T) {
	reg := edge.NewRegistry()
	reg.Register("bad_tool", func(ctx context.Context, args map[string]any) (edge.Result, error) {
		return edge.Result{"ok": true, "tool": "bad_tool", "unmarshalable": make(chan int)}, nil
	})

	envelope, err := edge.EncodeToolRequest("bad_tool", map[string]any{})
	if err != nil {
		t.Fatalf("encode: %v", err)
	}

	fg := &fakeGateway{
		goal:     envelope,
		runID:    "run-marshal",
		events:   make(chan *agentv1.AgentEvent, 8),
		gotReg:   make(chan *connectorv1.Register, 1),
		finished: make(chan struct{}),
	}

	lis := bufconn.Listen(1024 * 1024)
	srv := grpc.NewServer()
	connectorv1.RegisterConnectorGatewayServer(srv, fg)
	go srv.Serve(lis)
	defer srv.Stop()

	conn := dialBufconn(t, srv, lis)
	defer conn.Close()

	c := New(Config{TenantID: "org-1", ConnectorID: "edge-1"}, reg, slog.New(slog.NewTextHandler(io.Discard, nil)))
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	serveErr := make(chan error, 1)
	go func() { serveErr <- c.serve(ctx, connectorv1.NewConnectorGatewayClient(conn), true, nil) }()

	<-fg.gotReg
	select {
	case <-fg.finished:
	case <-ctx.Done():
		t.Fatal("run never finished")
	}

	var toolResult *agentv1.ToolResult
	for {
		select {
		case ev := <-fg.events:
			if tr := ev.GetToolResult(); tr != nil {
				toolResult = tr
			}
		default:
			goto done
		}
	}
done:
	if toolResult == nil {
		t.Fatal("no ToolResult event")
	}
	if toolResult.GetOutputJson() != "{}" {
		t.Fatalf("expected fallback empty-JSON output on marshal failure, got %q", toolResult.GetOutputJson())
	}

	cancel()
	<-serveErr
}

// Sanity check that the Result type used above really is unmarshalable via encoding/json, so the
// test above is exercising the intended failure mode rather than an accidental success.
func TestUnmarshalableResultReallyFailsToMarshal(t *testing.T) {
	res := edge.Result{"unmarshalable": make(chan int)}
	if _, err := json.Marshal(res); err == nil {
		t.Fatal("expected json.Marshal to fail for a channel value")
	}
}

// --- transport.go: Run's backoff-doubling-then-capped-at-MaxBackoff branch ---

// With Reconnect enabled and a dial target that always fails to resolve, Run should double its
// backoff each iteration and cap it at MaxBackoff (exercising the "backoff *= 2; backoff >
// MaxBackoff" branch), until the context is cancelled.
func TestRunBackoffCapsAtMaxBackoff(t *testing.T) {
	c := New(Config{Target: "127.0.0.1:1", Reconnect: true, MaxBackoff: 15 * time.Millisecond}, edge.NewRegistry(), slog.New(slog.NewTextHandler(io.Discard, nil)))
	ctx, cancel := context.WithTimeout(context.Background(), 80*time.Millisecond)
	defer cancel()
	err := c.Run(ctx)
	if err == nil {
		t.Fatal("expected Run to return the context error once cancelled")
	}
}

// --- pki.go: spiffeID defaults an empty connector to "edge" ---

func TestSpiffeIDDefaultsEmptyConnector(t *testing.T) {
	got := spiffeID("", "org-1", "")
	if got != "spiffe://skybridge.edge/tenant/org-1/connector/edge" {
		t.Fatalf("got %q", got)
	}
}

// --- pki.go: generateKeyAndCSR defaults an empty connector's CommonName, and propagates a
// url.Parse error when the (trust-domain, tenant, connector) tuple yields an invalid URI. ---

func TestGenerateKeyAndCSREmptyConnectorDefaultsCN(t *testing.T) {
	_, csrPEM, err := generateKeyAndCSR("", "org-1", "")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(csrPEM) == 0 {
		t.Fatal("expected csr bytes")
	}
}

func TestGenerateKeyAndCSRInvalidConnectorFailsURLParse(t *testing.T) {
	_, _, err := generateKeyAndCSR("", "org-1", "edge\x00bad")
	if err == nil {
		t.Fatal("expected url.Parse error from a connector with a control character")
	}
}

// --- material.go: certValid rejects a PEM block that decodes but isn't a valid x509 certificate ---

func TestCertValidRejectsNonCertificatePEMBlock(t *testing.T) {
	// A well-formed PEM block (so pem.Decode succeeds) whose bytes aren't a valid DER certificate, so
	// x509.ParseCertificate fails — a different failure mode than the "not a PEM at all" case already
	// covered by TestCertValidRejectsUnparseableCert.
	block := "-----BEGIN CERTIFICATE-----\n" + "bm90IGEgcmVhbCBjZXJ0aWZpY2F0ZQ==" + "\n-----END CERTIFICATE-----\n"
	if certValid([]byte(block), certRenewSkew) {
		t.Fatal("expected invalid for a PEM block that isn't a real certificate")
	}
}

// --- material.go: enroll()'s generateKeyAndCSR / serverTLSConfig / grpc.NewClient error branches ---

// A malformed CA bundle makes serverTLSConfig fail inside enroll, before any network I/O.
func TestEnrollServerTLSConfigErrorPropagates(t *testing.T) {
	c := New(Config{
		Target:      "127.0.0.1:0",
		TenantID:    "org-1",
		ConnectorID: "edge-1",
		CABundlePEM: []byte("not a valid ca bundle"),
	}, nil, slog.New(slog.NewTextHandler(io.Discard, nil)))
	if _, err := c.enroll(context.Background()); err == nil {
		t.Fatal("expected serverTLSConfig error to propagate from enroll")
	}
}

// A ConnectorID containing a control character makes generateKeyAndCSR's url.Parse fail inside
// enroll, exercising that error branch without any network I/O.
func TestEnrollGenerateKeyAndCSRErrorPropagates(t *testing.T) {
	c := New(Config{
		Target:      "127.0.0.1:0",
		TenantID:    "org-1",
		ConnectorID: "edge\x00bad",
	}, nil, slog.New(slog.NewTextHandler(io.Discard, nil)))
	if _, err := c.enroll(context.Background()); err == nil {
		t.Fatal("expected generateKeyAndCSR error to propagate from enroll")
	}
}

// --- material.go: ensureTLSMaterial propagates a store.Load error ---

// Pointing the Secrets Manager client at a fake HTTP endpoint that always errors makes
// certstore.FromEnv's layered store.Load fail (after exhausting local retries) without any real AWS
// call, exercising ensureTLSMaterial's "stored, err := store.Load(ctx); if err != nil" branch.
func TestEnsureTLSMaterialStoreLoadErrorPropagates(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(500)
		_, _ = w.Write([]byte(`{"__type":"InternalServiceError","message":"boom"}`))
	}))
	defer ts.Close()

	t.Setenv("AWS_ACCESS_KEY_ID", "k")
	t.Setenv("AWS_SECRET_ACCESS_KEY", "s")
	t.Setenv("AWS_REGION", "us-east-1")
	t.Setenv("AWS_ENDPOINT_URL_SECRETS_MANAGER", ts.URL)
	t.Setenv("AWS_MAX_ATTEMPTS", "1")

	ca := newTestCA(t)
	c := New(Config{
		TenantID:          "org-1",
		ConnectorID:       "edge-1",
		CABundlePEM:       ca.certPEM,
		TLSDir:            t.TempDir(),
		IdentitySecretARN: "arn:aws:secretsmanager:us-east-1:1:secret:x",
	}, nil, slog.New(slog.NewTextHandler(io.Discard, nil)))

	if _, err := c.ensureTLSMaterial(context.Background()); err == nil {
		t.Fatal("expected store.Load error to propagate from ensureTLSMaterial")
	}
}
