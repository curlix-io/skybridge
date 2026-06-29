package transport

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"log"
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

	c := New(Config{TenantID: "org-1", ConnectorID: "edge-1"}, reg, log.New(io.Discard, "", 0))

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	serveErr := make(chan error, 1)
	go func() { serveErr <- c.serve(ctx, connectorv1.NewConnectorGatewayClient(conn), true) }()

	select {
	case reg := <-fg.gotReg:
		if reg.GetTenantId() != "org-1" || reg.GetConnectorId() != "edge-1" {
			t.Fatalf("unexpected register: %+v", reg)
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

	c := New(Config{TenantID: "org-1", ConnectorID: "edge-1"}, edge.NewRegistry(), log.New(io.Discard, "", 0))

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	go func() { _ = c.serve(ctx, connectorv1.NewConnectorGatewayClient(conn), true) }()

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
