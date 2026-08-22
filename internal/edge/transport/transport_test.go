package transport

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net"
	"testing"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/test/bufconn"

	agentv1 "github.com/curlix-io/skybridge/internal/genpb/curlix/agent/v1"
	connectorv1 "github.com/curlix-io/skybridge/internal/genpb/curlix/connector/v1"

	"github.com/curlix-io/skybridge/internal/edge"
)

// fakeGateway is an in-process ConnectorGateway that, on Connect, waits for Register, dispatches one
// WorkAssignment carrying a tool envelope, then collects the connector's WorkEvents and reports them.
type fakeGateway struct {
	connectorv1.UnimplementedConnectorGatewayServer
	goal     string
	runID    string
	events   chan *agentv1.AgentEvent
	gotReg   chan *connectorv1.Register
	finished chan struct{}
}

func (g *fakeGateway) Connect(stream connectorv1.ConnectorGateway_ConnectServer) error {
	// First inbound message must be Register.
	first, err := stream.Recv()
	if err != nil {
		return err
	}
	reg := first.GetRegister()
	if reg == nil {
		return errors.New("expected Register first")
	}
	g.gotReg <- reg

	if err := stream.Send(&connectorv1.GatewayMessage{
		Msg: &connectorv1.GatewayMessage_Registered{Registered: &connectorv1.Registered{SessionId: "sess-1"}},
	}); err != nil {
		return err
	}
	if err := stream.Send(&connectorv1.GatewayMessage{
		Msg: &connectorv1.GatewayMessage_WorkAssignment{WorkAssignment: &connectorv1.WorkAssignment{
			RunId: g.runID,
			Start: &agentv1.StartRun{Goal: g.goal},
		}},
	}); err != nil {
		return err
	}

	for {
		msg, err := stream.Recv()
		if err != nil {
			if errors.Is(err, io.EOF) {
				return nil
			}
			return err
		}
		if we := msg.GetWorkEvent(); we != nil {
			ev := we.GetEvent()
			g.events <- ev
			if ev.GetFinished() != nil {
				close(g.finished)
				return nil
			}
		}
	}
}

func dialBufconn(t *testing.T, srv *grpc.Server, lis *bufconn.Listener) *grpc.ClientConn {
	t.Helper()
	conn, err := grpc.NewClient(
		"passthrough:///bufnet",
		grpc.WithContextDialer(func(ctx context.Context, _ string) (net.Conn, error) { return lis.DialContext(ctx) }),
		grpc.WithTransportCredentials(insecure.NewCredentials()),
	)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	return conn
}

func TestServeDispatchesToolEnvelope(t *testing.T) {
	envelope, err := edge.EncodeToolRequest("ping_tool", map[string]any{"x": float64(1)})
	if err != nil {
		t.Fatalf("encode: %v", err)
	}

	fg := &fakeGateway{
		goal:     envelope,
		runID:    "run-123",
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

	reg := edge.NewRegistry()
	reg.Register("ping_tool", func(ctx context.Context, args map[string]any) (edge.Result, error) {
		return edge.Result{"ok": true, "tool": "ping_tool", "echo": args["x"]}, nil
	})

	c := New(Config{TenantID: "org-1", ConnectorID: "edge-1"}, reg, slog.New(slog.NewTextHandler(io.Discard, nil)))

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	serveErr := make(chan error, 1)
	go func() { serveErr <- c.serve(ctx, connectorv1.NewConnectorGatewayClient(conn), true, nil) }()

	select {
	case reg := <-fg.gotReg:
		if reg.GetTenantId() != "org-1" || reg.GetConnectorId() != "edge-1" {
			t.Fatalf("unexpected register: %+v", reg)
		}
		// Regression: the SaaS side keys its connector registry by (tenant_id, agent_id) and the
		// in_cluster_agent credential broker / connectivity check look up a pinned connection's
		// kubernetes_clusters.agent_id (== ConnectorID) directly against that key -- if AgentId is
		// left unset here, every such lookup misses ("No in-cluster agent connector attached")
		// even though this connector is genuinely online, because it silently registered under
		// the org's default agent slot ("") instead of its own ConnectorID.
		if reg.GetAgentId() != "edge-1" {
			t.Fatalf("expected register.agent_id to equal ConnectorID %q, got %q", "edge-1", reg.GetAgentId())
		}
	case <-ctx.Done():
		t.Fatal("never received Register")
	}

	select {
	case <-fg.finished:
	case <-ctx.Done():
		t.Fatal("run never finished")
	}

	var toolResult *agentv1.ToolResult
	var runFinished *agentv1.RunFinished
	for {
		select {
		case ev := <-fg.events:
			if tr := ev.GetToolResult(); tr != nil {
				toolResult = tr
			}
			if rf := ev.GetFinished(); rf != nil {
				runFinished = rf
			}
		default:
			goto done
		}
	}
done:
	if toolResult == nil {
		t.Fatal("no ToolResult event")
	}
	if !toolResult.GetOk() || toolResult.GetName() != "ping_tool" {
		t.Fatalf("bad tool result: %+v", toolResult)
	}
	var out map[string]any
	if err := json.Unmarshal([]byte(toolResult.GetOutputJson()), &out); err != nil {
		t.Fatalf("output_json not json: %v", err)
	}
	if out["echo"] != float64(1) {
		t.Fatalf("echo not propagated: %+v", out)
	}
	if runFinished == nil {
		t.Fatal("no RunFinished event")
	}
	var resp map[string]any
	if err := json.Unmarshal([]byte(runFinished.GetResponseJson()), &resp); err != nil {
		t.Fatalf("response_json not json: %v", err)
	}
	if resp["stopped_reason"] != "final_answer" {
		t.Fatalf("unexpected stopped_reason: %+v", resp)
	}

	cancel()
	<-serveErr
}

func TestServeRejectsNonEnvelopeGoal(t *testing.T) {
	fg := &fakeGateway{
		goal:     "why is the database slow?",
		runID:    "run-xyz",
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

	c := New(Config{TenantID: "org-1", ConnectorID: "edge-1"}, edge.NewRegistry(), slog.New(slog.NewTextHandler(io.Discard, nil)))

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	go func() { _ = c.serve(ctx, connectorv1.NewConnectorGatewayClient(conn), true, nil) }()

	<-fg.gotReg
	select {
	case <-fg.finished:
	case <-ctx.Done():
		t.Fatal("run never finished")
	}

	var runFinished *agentv1.RunFinished
	for {
		select {
		case ev := <-fg.events:
			if rf := ev.GetFinished(); rf != nil {
				runFinished = rf
			}
		default:
			goto done
		}
	}
done:
	if runFinished == nil {
		t.Fatal("no RunFinished event")
	}
	var resp map[string]any
	if err := json.Unmarshal([]byte(runFinished.GetResponseJson()), &resp); err != nil {
		t.Fatalf("response_json not json: %v", err)
	}
	if resp["stopped_reason"] != "error" {
		t.Fatalf("expected error stop, got: %+v", resp)
	}
}

// fakeGatewayPing registers the connector then sends a Ping, waiting for the connector's Heartbeat
// reply before ending the stream cleanly (io.EOF on the client side).
type fakeGatewayPing struct {
	connectorv1.UnimplementedConnectorGatewayServer
	gotReg       chan *connectorv1.Register
	gotHeartbeat chan struct{}
}

func (g *fakeGatewayPing) Connect(stream connectorv1.ConnectorGateway_ConnectServer) error {
	first, err := stream.Recv()
	if err != nil {
		return err
	}
	if first.GetRegister() == nil {
		return errors.New("expected Register first")
	}
	g.gotReg <- first.GetRegister()

	if err := stream.Send(&connectorv1.GatewayMessage{
		Msg: &connectorv1.GatewayMessage_Ping{Ping: &connectorv1.Ping{}},
	}); err != nil {
		return err
	}

	for {
		msg, err := stream.Recv()
		if err != nil {
			if errors.Is(err, io.EOF) {
				return nil
			}
			return err
		}
		if msg.GetHeartbeat() != nil {
			select {
			case g.gotHeartbeat <- struct{}{}:
			default:
			}
			return nil // end the stream cleanly once we've observed the heartbeat
		}
	}
}

func TestServeRespondsToPingWithHeartbeat(t *testing.T) {
	fg := &fakeGatewayPing{
		gotReg:       make(chan *connectorv1.Register, 1),
		gotHeartbeat: make(chan struct{}, 1),
	}

	lis := bufconn.Listen(1024 * 1024)
	srv := grpc.NewServer()
	connectorv1.RegisterConnectorGatewayServer(srv, fg)
	go srv.Serve(lis)
	defer srv.Stop()

	conn := dialBufconn(t, srv, lis)
	defer conn.Close()

	c := New(Config{TenantID: "org-1", ConnectorID: "edge-1"}, edge.NewRegistry(), slog.New(slog.NewTextHandler(io.Discard, nil)))

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	serveErr := make(chan error, 1)
	go func() { serveErr <- c.serve(ctx, connectorv1.NewConnectorGatewayClient(conn), true, nil) }()

	select {
	case <-fg.gotReg:
	case <-ctx.Done():
		t.Fatal("never received Register")
	}
	select {
	case <-fg.gotHeartbeat:
	case <-ctx.Done():
		t.Fatal("never received heartbeat")
	}
	select {
	case err := <-serveErr:
		if err != nil {
			t.Fatalf("serve returned error: %v", err)
		}
	case <-ctx.Done():
		t.Fatal("serve did not return after server closed stream")
	}
}

// fakeGatewayConnectErr always rejects Connect, exercising the dial-error path of serve.
type fakeGatewayConnectErr struct {
	connectorv1.UnimplementedConnectorGatewayServer
}

func (fakeGatewayConnectErr) Connect(stream connectorv1.ConnectorGateway_ConnectServer) error {
	return errors.New("connect rejected")
}

func TestServeReturnsErrorWhenStreamRejected(t *testing.T) {
	fg := fakeGatewayConnectErr{}
	lis := bufconn.Listen(1024 * 1024)
	srv := grpc.NewServer()
	connectorv1.RegisterConnectorGatewayServer(srv, fg)
	go srv.Serve(lis)
	defer srv.Stop()

	conn := dialBufconn(t, srv, lis)
	defer conn.Close()

	c := New(Config{TenantID: "org-1", ConnectorID: "edge-1"}, edge.NewRegistry(), slog.New(slog.NewTextHandler(io.Discard, nil)))
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	err := c.serve(ctx, connectorv1.NewConnectorGatewayClient(conn), true, nil)
	if err == nil {
		t.Fatal("expected error from rejected stream")
	}
}

func TestCancelWorkCancelsTrackedRun(t *testing.T) {
	c := New(Config{TenantID: "org-1", ConnectorID: "edge-1"}, edge.NewRegistry(), slog.New(slog.NewTextHandler(io.Discard, nil)))

	runCtx, cancel := context.WithCancel(context.Background())
	c.mu.Lock()
	c.runs["run-1"] = cancel
	c.mu.Unlock()

	c.cancelWork("run-1")
	select {
	case <-runCtx.Done():
	case <-time.After(time.Second):
		t.Fatal("cancelWork did not cancel run context")
	}

	// Cancelling an unknown run id must be a no-op, not a panic.
	c.cancelWork("does-not-exist")
}

func TestStartWorkIgnoresEmptyRunID(t *testing.T) {
	c := New(Config{TenantID: "org-1", ConnectorID: "edge-1"}, edge.NewRegistry(), slog.New(slog.NewTextHandler(io.Discard, nil)))
	c.startWork(context.Background(), &safeStream{}, &connectorv1.WorkAssignment{RunId: ""})
	c.mu.Lock()
	n := len(c.runs)
	c.mu.Unlock()
	if n != 0 {
		t.Fatalf("expected no run tracked for empty run id, got %d", n)
	}
}

func TestStartWorkDuplicateRunIDIsRejected(t *testing.T) {
	c := New(Config{TenantID: "org-1", ConnectorID: "edge-1"}, edge.NewRegistry(), slog.New(slog.NewTextHandler(io.Discard, nil)))
	c.mu.Lock()
	c.runs["dup"] = func() {}
	c.mu.Unlock()

	// startWork on a duplicate run id must return before ever touching ss, so a nil stream here is
	// safe and proves the early-return path.
	c.startWork(context.Background(), nil, &connectorv1.WorkAssignment{RunId: "dup"})

	c.mu.Lock()
	n := len(c.runs)
	c.mu.Unlock()
	if n != 1 {
		t.Fatalf("expected duplicate run id to be ignored, got %d runs", n)
	}
}

func TestDialProducesClientForInsecureAndSystemRoots(t *testing.T) {
	c := New(Config{Target: "127.0.0.1:0", Insecure: true}, edge.NewRegistry(), slog.New(slog.NewTextHandler(io.Discard, nil)))
	conn, err := c.dial(nil)
	if err != nil {
		t.Fatalf("dial insecure: %v", err)
	}
	_ = conn.Close()

	c2 := New(Config{Target: "127.0.0.1:0"}, edge.NewRegistry(), slog.New(slog.NewTextHandler(io.Discard, nil)))
	conn2, err := c2.dial(nil)
	if err != nil {
		t.Fatalf("dial system-roots TLS: %v", err)
	}
	_ = conn2.Close()
}

// TestDialWithForceBearerAndCABundleTrustsPrivateCA is a regression test for the bug where the
// connector-gateway's bearer mode (SKYBRIDGE_CONNECTOR_KEY set) ignored CABundlePEM entirely and
// fell through to system roots, failing every dial against a gateway whose cert is issued by a
// private CA (the CA embedded in the connector key itself) with "x509: certificate signed by
// unknown authority". ensureTLSMaterial's ForceBearer branch always returns (nil, nil), so dial()
// must consult c.cfg.CABundlePEM directly rather than the material — mirrors studiotransport's
// dial(), which already handles this for the Query Studio gateway.
func TestDialWithForceBearerAndCABundleTrustsPrivateCA(t *testing.T) {
	ca := newTestCA(t)
	c := New(Config{
		Target:      "127.0.0.1:0",
		ForceBearer: true,
		CABundlePEM: ca.certPEM,
	}, edge.NewRegistry(), slog.New(slog.NewTextHandler(io.Discard, nil)))

	material, err := c.ensureTLSMaterial(context.Background())
	if err != nil {
		t.Fatalf("ensureTLSMaterial: %v", err)
	}
	if material != nil {
		t.Fatalf("expected ForceBearer to skip mTLS material entirely, got %v", material)
	}

	conn, err := c.dial(material)
	if err != nil {
		t.Fatalf("dial bearer with private CA: %v", err)
	}
	_ = conn.Close()
}

// TestDialWithForceBearerAndInvalidCABundleFails ensures a malformed CABundlePEM in bearer mode
// surfaces as an error from dial() rather than silently falling back to system roots.
func TestDialWithForceBearerAndInvalidCABundleFails(t *testing.T) {
	c := New(Config{
		Target:      "127.0.0.1:0",
		ForceBearer: true,
		CABundlePEM: []byte("not a pem"),
	}, edge.NewRegistry(), slog.New(slog.NewTextHandler(io.Discard, nil)))

	if _, err := c.dial(nil); err == nil {
		t.Fatal("expected dial to fail on invalid CA bundle PEM")
	}
}

func TestRunFatalConfigErrorReturnsWithoutReconnect(t *testing.T) {
	ca := newTestCA(t)
	c := New(Config{
		Target:      "127.0.0.1:0",
		TenantID:    "org-1",
		ConnectorID: "edge-1",
		CABundlePEM: ca.certPEM,
		TLSDir:      t.TempDir(), // no cert on disk, no enroll token -> fatal
	}, edge.NewRegistry(), slog.New(slog.NewTextHandler(io.Discard, nil)))

	err := c.Run(context.Background())
	if err == nil {
		t.Fatal("expected fatal config error from Run")
	}
}

func TestRunReconnectsUntilContextCancelled(t *testing.T) {
	c := New(Config{Target: "127.0.0.1:1", Reconnect: true, MaxBackoff: 5 * time.Millisecond}, edge.NewRegistry(), slog.New(slog.NewTextHandler(io.Discard, nil)))
	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()
	err := c.Run(ctx)
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("expected context.DeadlineExceeded, got %v", err)
	}
}
