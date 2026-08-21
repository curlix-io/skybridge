package transport

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"net"
	"testing"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/grpc/test/bufconn"

	connectorv1 "github.com/curlix-io/skybridge/internal/genpb/curlix/connector/v1"

	"github.com/curlix-io/skybridge/internal/edge"
)

// §10.3 (docs/design/skybridge-masking-architecture.md in curlix/curlix): pre-connect admission,
// backoff-reset-on-stable-connection, and auth-failure classification.

func TestPreConnectProceedsWhenGatewayDoesNotImplementIt(t *testing.T) {
	// UnimplementedConnectorGatewayServer's PreConnect returns codes.Unimplemented.
	lis := bufconn.Listen(1024 * 1024)
	srv := grpc.NewServer()
	connectorv1.RegisterConnectorGatewayServer(srv, &connectorv1.UnimplementedConnectorGatewayServer{})
	go srv.Serve(lis)
	defer srv.Stop()

	conn := dialBufconn(t, srv, lis)
	defer conn.Close()

	c := New(Config{TenantID: "org-1", ConnectorID: "edge-1"}, edge.NewRegistry(), slog.New(slog.NewTextHandler(io.Discard, nil)))
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	ok, retryAfter, reason := c.preConnect(ctx, connectorv1.NewConnectorGatewayClient(conn), true, nil)
	if !ok {
		t.Fatalf("expected ok=true (fail-open) when PreConnect is unimplemented, got ok=false reason=%q", reason)
	}
	if retryAfter != 0 {
		t.Fatalf("expected retryAfter=0 on fail-open, got %v", retryAfter)
	}
}

// fakeGatewayPreConnect implements PreConnect with a configurable response and Connect trivially.
type fakeGatewayPreConnect struct {
	connectorv1.UnimplementedConnectorGatewayServer
	resp *connectorv1.PreConnectResponse
	err  error

	preConnectCalls chan *connectorv1.PreConnectRequest
	connectCalls    chan struct{}
}

func (g *fakeGatewayPreConnect) PreConnect(_ context.Context, req *connectorv1.PreConnectRequest) (*connectorv1.PreConnectResponse, error) {
	if g.preConnectCalls != nil {
		select {
		case g.preConnectCalls <- req:
		default:
		}
	}
	if g.err != nil {
		return nil, g.err
	}
	return g.resp, nil
}

func (g *fakeGatewayPreConnect) Connect(stream connectorv1.ConnectorGateway_ConnectServer) error {
	if g.connectCalls != nil {
		select {
		case g.connectCalls <- struct{}{}:
		default:
		}
	}
	// Register, ack, then end cleanly.
	first, err := stream.Recv()
	if err != nil {
		return err
	}
	if first.GetRegister() == nil {
		return errors.New("expected Register first")
	}
	if err := stream.Send(&connectorv1.GatewayMessage{
		Msg: &connectorv1.GatewayMessage_Registered{Registered: &connectorv1.Registered{SessionId: "sess-1"}},
	}); err != nil {
		return err
	}
	return nil
}

func TestPreConnectReturnsWaitWithReasonAndRetryAfter(t *testing.T) {
	fg := &fakeGatewayPreConnect{
		resp: &connectorv1.PreConnectResponse{Ok: false, RetryAfterSeconds: 7, Reason: "gateway draining"},
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

	ok, retryAfter, reason := c.preConnect(ctx, connectorv1.NewConnectorGatewayClient(conn), true, nil)
	if ok {
		t.Fatal("expected ok=false")
	}
	if retryAfter != 7*time.Second {
		t.Fatalf("expected retryAfter=7s, got %v", retryAfter)
	}
	if reason != "gateway draining" {
		t.Fatalf("expected reason %q, got %q", "gateway draining", reason)
	}
}

func TestPreConnectClampsSubSecondRetryAfterToOneSecond(t *testing.T) {
	fg := &fakeGatewayPreConnect{
		resp: &connectorv1.PreConnectResponse{Ok: false, RetryAfterSeconds: 0, Reason: "identity revoked"},
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

	ok, retryAfter, _ := c.preConnect(ctx, connectorv1.NewConnectorGatewayClient(conn), true, nil)
	if ok {
		t.Fatal("expected ok=false")
	}
	if retryAfter != time.Second {
		t.Fatalf("expected retryAfter clamped to 1s, got %v", retryAfter)
	}
}

func TestRunSkipsConnectWhilePreConnectSaysWaitThenProceeds(t *testing.T) {
	preConnectCalls := make(chan *connectorv1.PreConnectRequest, 10)
	connectCalls := make(chan struct{}, 10)

	callCount := 0
	fg := &preConnectGateStub{
		preConnectCalls: preConnectCalls,
		connectCalls:    connectCalls,
		respond: func() *connectorv1.PreConnectResponse {
			callCount++
			if callCount < 3 {
				return &connectorv1.PreConnectResponse{Ok: false, RetryAfterSeconds: 1, Reason: "draining"}
			}
			return &connectorv1.PreConnectResponse{Ok: true}
		},
	}

	lis, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	srv := grpc.NewServer()
	connectorv1.RegisterConnectorGatewayServer(srv, fg)
	go srv.Serve(lis)
	defer srv.Stop()

	c := New(Config{
		Target:      lis.Addr().String(),
		TenantID:    "org-1",
		ConnectorID: "edge-1",
		Insecure:    true,
		Reconnect:   true,
		MaxBackoff:  time.Second,
	}, edge.NewRegistry(), slog.New(slog.NewTextHandler(io.Discard, nil)))

	ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
	defer cancel()

	done := make(chan error, 1)
	go func() { done <- c.Run(ctx) }()

	// Wait until Connect has actually been reached (i.e. PreConnect eventually said ok).
	select {
	case <-connectCalls:
	case <-ctx.Done():
		t.Fatal("Connect was never reached after PreConnect started allowing it")
	}
	cancel()
	<-done

	if callCount < 3 {
		t.Fatalf("expected at least 3 PreConnect calls before ok=true, got %d", callCount)
	}
}

// preConnectGateStub is a minimal fake gateway whose PreConnect response is produced by a
// caller-supplied function, and whose Connect just registers and returns.
type preConnectGateStub struct {
	connectorv1.UnimplementedConnectorGatewayServer
	preConnectCalls chan *connectorv1.PreConnectRequest
	connectCalls    chan struct{}
	respond         func() *connectorv1.PreConnectResponse
}

func (g *preConnectGateStub) PreConnect(_ context.Context, req *connectorv1.PreConnectRequest) (*connectorv1.PreConnectResponse, error) {
	select {
	case g.preConnectCalls <- req:
	default:
	}
	return g.respond(), nil
}

func (g *preConnectGateStub) Connect(stream connectorv1.ConnectorGateway_ConnectServer) error {
	select {
	case g.connectCalls <- struct{}{}:
	default:
	}
	first, err := stream.Recv()
	if err != nil {
		return err
	}
	if first.GetRegister() == nil {
		return errors.New("expected Register first")
	}
	return stream.Send(&connectorv1.GatewayMessage{
		Msg: &connectorv1.GatewayMessage_Registered{Registered: &connectorv1.Registered{SessionId: "sess-1"}},
	})
}

// authFailureGateway always rejects Connect with Unauthenticated, so Run() must classify it and
// float the retry sleep at authFailureBackoffFloor instead of the ordinary backoff ladder.
type authFailureGateway struct {
	connectorv1.UnimplementedConnectorGatewayServer
	connectAttempts chan struct{}
}

func (g *authFailureGateway) PreConnect(context.Context, *connectorv1.PreConnectRequest) (*connectorv1.PreConnectResponse, error) {
	return &connectorv1.PreConnectResponse{Ok: true}, nil
}

func (g *authFailureGateway) Connect(_ connectorv1.ConnectorGateway_ConnectServer) error {
	select {
	case g.connectAttempts <- struct{}{}:
	default:
	}
	return status.Error(codes.Unauthenticated, "token expired")
}

func TestRunFloorsRetryAtAuthFailureBackoffOnUnauthenticated(t *testing.T) {
	old := authFailureBackoffFloor
	authFailureBackoffFloor = 300 * time.Millisecond // shrink for a fast, deterministic test
	defer func() { authFailureBackoffFloor = old }()

	attempts := make(chan struct{}, 10)
	fg := &authFailureGateway{connectAttempts: attempts}

	lis, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	srv := grpc.NewServer()
	connectorv1.RegisterConnectorGatewayServer(srv, fg)
	go srv.Serve(lis)
	defer srv.Stop()

	c := New(Config{
		Target:      lis.Addr().String(),
		TenantID:    "org-1",
		ConnectorID: "edge-1",
		Insecure:    true,
		Reconnect:   true,
		MaxBackoff:  50 * time.Millisecond, // ordinary ladder would retry far faster than the floor
	}, edge.NewRegistry(), slog.New(slog.NewTextHandler(io.Discard, nil)))

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	done := make(chan error, 1)
	go func() { done <- c.Run(ctx) }()

	// First Connect attempt.
	select {
	case <-attempts:
	case <-ctx.Done():
		t.Fatal("first Connect attempt never happened")
	}
	firstAttempt := time.Now()

	// Second Connect attempt should be floored at ~authFailureBackoffFloor (300ms jittered to
	// [150ms, 300ms)), not the tiny 50ms MaxBackoff ladder.
	select {
	case <-attempts:
	case <-ctx.Done():
		t.Fatal("second Connect attempt never happened")
	}
	elapsed := time.Since(firstAttempt)
	if elapsed < authFailureBackoffFloor/2 {
		t.Fatalf("expected retry floored near auth-failure backoff (>= %v), got %v", authFailureBackoffFloor/2, elapsed)
	}

	cancel()
	<-done
}

func TestRunResetsBackoffOnlyAfterStableConnection(t *testing.T) {
	old := backoffResetAfter
	backoffResetAfter = 200 * time.Millisecond // shrink for a fast, deterministic test
	defer func() { backoffResetAfter = old }()

	attempt := 0
	attemptTimes := make(chan time.Time, 10)

	lis, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	srv := grpc.NewServer()
	fg := &stableConnGateway{
		onConnect: func() time.Duration {
			attempt++
			attemptTimes <- time.Now()
			if attempt <= 2 {
				return 0 // drop immediately -- not stable, backoff keeps escalating (1s -> 2s)
			}
			return 300 * time.Millisecond // stable -- must reset backoff to baseline afterward
		},
	}
	connectorv1.RegisterConnectorGatewayServer(srv, fg)
	go srv.Serve(lis)
	defer srv.Stop()

	c := New(Config{
		Target:      lis.Addr().String(),
		TenantID:    "org-1",
		ConnectorID: "edge-1",
		Insecure:    true,
		Reconnect:   true,
		MaxBackoff:  5 * time.Second,
	}, edge.NewRegistry(), slog.New(slog.NewTextHandler(io.Discard, nil)))

	ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
	defer cancel()

	done := make(chan error, 1)
	go func() { done <- c.Run(ctx) }()

	<-attemptTimes       // attempt 1 (unstable, backoff still baseline 1s going in)
	t2 := <-attemptTimes // attempt 2 (unstable, backoff now 2s going in, after attempt 1's sleep)
	t3 := <-attemptTimes // attempt 3 (stable 300ms; backoff was 4s going in, but that's irrelevant)
	t4 := <-attemptTimes // attempt 4 -- the sleep before it used the RESET backoff (1s), not 4s

	gapAfterSecondDrop := t3.Sub(t2)                        // jittered(2s) in [1s, 2s)
	gapAfterStableConn := t4.Sub(t3) - 300*time.Millisecond // jittered(1s) in [0.5s, 1s) if reset

	// Without the fix, backoff would have kept escalating (jittered(4s) in [2s,4s)) instead of
	// resetting to baseline after the stable third connection -- so the post-reset gap must be
	// strictly smaller than the pre-reset gap, not just "close".
	if gapAfterStableConn >= gapAfterSecondDrop {
		t.Fatalf("expected backoff to reset to baseline after a stable connection: gap before reset (attempt2->3, backoff=2s)=%v, gap after reset (attempt3->4, should be backoff=1s)=%v",
			gapAfterSecondDrop, gapAfterStableConn)
	}

	cancel()
	<-done
}

// stableConnGateway's Connect blocks for onConnect()'s returned duration (simulating a
// connection that stays open that long) before returning cleanly (io.EOF-equivalent nil).
type stableConnGateway struct {
	connectorv1.UnimplementedConnectorGatewayServer
	onConnect func() time.Duration
}

func (g *stableConnGateway) PreConnect(context.Context, *connectorv1.PreConnectRequest) (*connectorv1.PreConnectResponse, error) {
	return &connectorv1.PreConnectResponse{Ok: true}, nil
}

func (g *stableConnGateway) Connect(stream connectorv1.ConnectorGateway_ConnectServer) error {
	dur := g.onConnect()
	first, err := stream.Recv()
	if err != nil {
		return err
	}
	if first.GetRegister() == nil {
		return errors.New("expected Register first")
	}
	if err := stream.Send(&connectorv1.GatewayMessage{
		Msg: &connectorv1.GatewayMessage_Registered{Registered: &connectorv1.Registered{SessionId: "sess-1"}},
	}); err != nil {
		return err
	}
	if dur > 0 {
		time.Sleep(dur)
	}
	return nil
}
