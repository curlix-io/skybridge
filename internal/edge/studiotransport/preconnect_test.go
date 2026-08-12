package studiotransport

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
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/status"
	"google.golang.org/grpc/test/bufconn"

	studiov1 "github.com/curlix-io/skybridge/internal/genpb/curlix/studiogateway/v1"
)

// §10.3 (docs/design/skybridge-masking-architecture.md in curlix/curlix): pre-connect admission,
// backoff-reset-on-stable-connection, and auth-failure classification. Mirrors
// internal/edge/transport/preconnect_test.go.

func dialStudioBufconn(t *testing.T, lis *bufconn.Listener) *grpc.ClientConn {
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

func TestPreConnectProceedsWhenGatewayDoesNotImplementIt(t *testing.T) {
	lis := bufconn.Listen(1024 * 1024)
	srv := grpc.NewServer()
	studiov1.RegisterStudioGatewayServer(srv, &studiov1.UnimplementedStudioGatewayServer{})
	go srv.Serve(lis)
	defer srv.Stop()

	conn := dialStudioBufconn(t, lis)
	defer conn.Close()

	c := New(Config{TenantID: "org-1", AgentID: "agent-1"}, slog.New(slog.NewTextHandler(io.Discard, nil)))
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	ok, retryAfter, reason := c.preConnect(ctx, studiov1.NewStudioGatewayClient(conn), true)
	if !ok {
		t.Fatalf("expected ok=true (fail-open) when PreConnect is unimplemented, got ok=false reason=%q", reason)
	}
	if retryAfter != 0 {
		t.Fatalf("expected retryAfter=0 on fail-open, got %v", retryAfter)
	}
}

type fakeStudioGatewayPreConnect struct {
	studiov1.UnimplementedStudioGatewayServer
	resp *studiov1.PreConnectResponse
}

func (g *fakeStudioGatewayPreConnect) PreConnect(context.Context, *studiov1.PreConnectRequest) (*studiov1.PreConnectResponse, error) {
	return g.resp, nil
}

func TestPreConnectReturnsWaitWithReasonAndRetryAfter(t *testing.T) {
	fg := &fakeStudioGatewayPreConnect{resp: &studiov1.PreConnectResponse{Ok: false, RetryAfterSeconds: 7, Reason: "gateway draining"}}
	lis := bufconn.Listen(1024 * 1024)
	srv := grpc.NewServer()
	studiov1.RegisterStudioGatewayServer(srv, fg)
	go srv.Serve(lis)
	defer srv.Stop()

	conn := dialStudioBufconn(t, lis)
	defer conn.Close()

	c := New(Config{TenantID: "org-1", AgentID: "agent-1"}, slog.New(slog.NewTextHandler(io.Discard, nil)))
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	ok, retryAfter, reason := c.preConnect(ctx, studiov1.NewStudioGatewayClient(conn), true)
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
	fg := &fakeStudioGatewayPreConnect{resp: &studiov1.PreConnectResponse{Ok: false, RetryAfterSeconds: 0, Reason: "identity revoked"}}
	lis := bufconn.Listen(1024 * 1024)
	srv := grpc.NewServer()
	studiov1.RegisterStudioGatewayServer(srv, fg)
	go srv.Serve(lis)
	defer srv.Stop()

	conn := dialStudioBufconn(t, lis)
	defer conn.Close()

	c := New(Config{TenantID: "org-1", AgentID: "agent-1"}, slog.New(slog.NewTextHandler(io.Discard, nil)))
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	ok, retryAfter, _ := c.preConnect(ctx, studiov1.NewStudioGatewayClient(conn), true)
	if ok {
		t.Fatal("expected ok=false")
	}
	if retryAfter != time.Second {
		t.Fatalf("expected retryAfter clamped to 1s, got %v", retryAfter)
	}
}

// preConnectGateStub is a minimal fake gateway whose PreConnect response is produced by a
// caller-supplied function, and whose Connect just registers and returns.
type preConnectGateStub struct {
	studiov1.UnimplementedStudioGatewayServer
	connectCalls chan struct{}
	respond      func() *studiov1.PreConnectResponse
}

func (g *preConnectGateStub) PreConnect(context.Context, *studiov1.PreConnectRequest) (*studiov1.PreConnectResponse, error) {
	return g.respond(), nil
}

func (g *preConnectGateStub) Connect(stream studiov1.StudioGateway_ConnectServer) error {
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
	return stream.Send(&studiov1.GatewayMessage{
		Msg: &studiov1.GatewayMessage_Registered{Registered: &studiov1.Registered{LeaseId: "lease-1"}},
	})
}

func TestRunSkipsConnectWhilePreConnectSaysWaitThenProceeds(t *testing.T) {
	connectCalls := make(chan struct{}, 10)
	callCount := 0
	fg := &preConnectGateStub{
		connectCalls: connectCalls,
		respond: func() *studiov1.PreConnectResponse {
			callCount++
			if callCount < 3 {
				return &studiov1.PreConnectResponse{Ok: false, RetryAfterSeconds: 1, Reason: "draining"}
			}
			return &studiov1.PreConnectResponse{Ok: true}
		},
	}

	lis, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	srv := grpc.NewServer()
	studiov1.RegisterStudioGatewayServer(srv, fg)
	go srv.Serve(lis)
	defer srv.Stop()

	c := New(Config{
		Target:     lis.Addr().String(),
		TenantID:   "org-1",
		AgentID:    "agent-1",
		Insecure:   true,
		Reconnect:  true,
		MaxBackoff: time.Second,
	}, slog.New(slog.NewTextHandler(io.Discard, nil)))

	ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
	defer cancel()

	done := make(chan error, 1)
	go func() { done <- c.Run(ctx) }()

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

type authFailureGateway struct {
	studiov1.UnimplementedStudioGatewayServer
	connectAttempts chan struct{}
}

func (g *authFailureGateway) PreConnect(context.Context, *studiov1.PreConnectRequest) (*studiov1.PreConnectResponse, error) {
	return &studiov1.PreConnectResponse{Ok: true}, nil
}

func (g *authFailureGateway) Connect(_ studiov1.StudioGateway_ConnectServer) error {
	select {
	case g.connectAttempts <- struct{}{}:
	default:
	}
	return status.Error(codes.Unauthenticated, "token expired")
}

func TestRunFloorsRetryAtAuthFailureBackoffOnUnauthenticated(t *testing.T) {
	old := authFailureBackoffFloor
	authFailureBackoffFloor = 300 * time.Millisecond
	defer func() { authFailureBackoffFloor = old }()

	attempts := make(chan struct{}, 10)
	fg := &authFailureGateway{connectAttempts: attempts}

	lis, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	srv := grpc.NewServer()
	studiov1.RegisterStudioGatewayServer(srv, fg)
	go srv.Serve(lis)
	defer srv.Stop()

	c := New(Config{
		Target:     lis.Addr().String(),
		TenantID:   "org-1",
		AgentID:    "agent-1",
		Insecure:   true,
		Reconnect:  true,
		MaxBackoff: 50 * time.Millisecond,
	}, slog.New(slog.NewTextHandler(io.Discard, nil)))

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	done := make(chan error, 1)
	go func() { done <- c.Run(ctx) }()

	select {
	case <-attempts:
	case <-ctx.Done():
		t.Fatal("first Connect attempt never happened")
	}
	firstAttempt := time.Now()

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

type stableConnGateway struct {
	studiov1.UnimplementedStudioGatewayServer
	onConnect func() time.Duration
}

func (g *stableConnGateway) PreConnect(context.Context, *studiov1.PreConnectRequest) (*studiov1.PreConnectResponse, error) {
	return &studiov1.PreConnectResponse{Ok: true}, nil
}

func (g *stableConnGateway) Connect(stream studiov1.StudioGateway_ConnectServer) error {
	dur := g.onConnect()
	first, err := stream.Recv()
	if err != nil {
		return err
	}
	if first.GetRegister() == nil {
		return errors.New("expected Register first")
	}
	if err := stream.Send(&studiov1.GatewayMessage{
		Msg: &studiov1.GatewayMessage_Registered{Registered: &studiov1.Registered{LeaseId: "lease-1"}},
	}); err != nil {
		return err
	}
	if dur > 0 {
		time.Sleep(dur)
	}
	return nil
}

func TestRunResetsBackoffOnlyAfterStableConnection(t *testing.T) {
	old := backoffResetAfter
	backoffResetAfter = 200 * time.Millisecond
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
				return 0
			}
			return 300 * time.Millisecond
		},
	}
	studiov1.RegisterStudioGatewayServer(srv, fg)
	go srv.Serve(lis)
	defer srv.Stop()

	c := New(Config{
		Target:     lis.Addr().String(),
		TenantID:   "org-1",
		AgentID:    "agent-1",
		Insecure:   true,
		Reconnect:  true,
		MaxBackoff: 5 * time.Second,
	}, slog.New(slog.NewTextHandler(io.Discard, nil)))

	ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
	defer cancel()

	done := make(chan error, 1)
	go func() { done <- c.Run(ctx) }()

	<-attemptTimes
	t2 := <-attemptTimes
	t3 := <-attemptTimes
	t4 := <-attemptTimes

	gapAfterSecondDrop := t3.Sub(t2)
	gapAfterStableConn := t4.Sub(t3) - 300*time.Millisecond

	if gapAfterStableConn >= gapAfterSecondDrop {
		t.Fatalf("expected backoff to reset to baseline after a stable connection: gap before reset=%v, gap after reset=%v",
			gapAfterSecondDrop, gapAfterStableConn)
	}

	cancel()
	<-done
}
