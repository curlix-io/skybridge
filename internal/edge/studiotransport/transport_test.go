package studiotransport

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"sync"
	"testing"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/metadata"

	studiov1 "github.com/curlix-io/skybridge/internal/genpb/curlix/studiogateway/v1"
)

// fakeBidiStream is a minimal grpc.BidiStreamingClient[AgentMessage, GatewayMessage] fake driven by
// two channels, so serve()/heartbeatLoop() can be exercised without a real gRPC connection.
type fakeBidiStream struct {
	sendCh  chan *studiov1.AgentMessage
	recvCh  chan *studiov1.GatewayMessage
	recvErr error
	closed  chan struct{}
	once    sync.Once
}

func newFakeBidiStream() *fakeBidiStream {
	return &fakeBidiStream{
		sendCh: make(chan *studiov1.AgentMessage, 64),
		recvCh: make(chan *studiov1.GatewayMessage, 64),
		closed: make(chan struct{}),
	}
}

func (f *fakeBidiStream) Send(m *studiov1.AgentMessage) error {
	select {
	case f.sendCh <- m:
		return nil
	case <-f.closed:
		return errors.New("stream closed")
	}
}

func (f *fakeBidiStream) Recv() (*studiov1.GatewayMessage, error) {
	select {
	case m, ok := <-f.recvCh:
		if !ok {
			return nil, io.EOF
		}
		return m, nil
	case <-f.closed:
		if f.recvErr != nil {
			return nil, f.recvErr
		}
		return nil, io.EOF
	}
}

func (f *fakeBidiStream) closeStream() { f.once.Do(func() { close(f.closed) }) }

func (f *fakeBidiStream) Header() (metadata.MD, error) { return nil, nil }
func (f *fakeBidiStream) Trailer() metadata.MD         { return nil }
func (f *fakeBidiStream) CloseSend() error             { return nil }
func (f *fakeBidiStream) Context() context.Context     { return context.Background() }
func (f *fakeBidiStream) SendMsg(m any) error          { return nil }
func (f *fakeBidiStream) RecvMsg(m any) error          { return nil }

func drainRegister(t *testing.T, f *fakeBidiStream) *studiov1.Register {
	t.Helper()
	select {
	case m := <-f.sendCh:
		reg := m.GetRegister()
		if reg == nil {
			t.Fatalf("expected the first sent message to be a Register, got %+v", m)
		}
		return reg
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for Register")
		return nil
	}
}

func TestSafeStreamSendIsConcurrencySafe(t *testing.T) {
	f := newFakeBidiStream()
	ss := &safeStream{stream: f}
	var wg sync.WaitGroup
	for i := 0; i < 20; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_ = ss.send(&studiov1.AgentMessage{Msg: &studiov1.AgentMessage_Heartbeat{Heartbeat: &studiov1.Heartbeat{}}})
		}()
	}
	wg.Wait()
	if len(f.sendCh) != 20 {
		t.Fatalf("expected 20 sent messages, got %d", len(f.sendCh))
	}
}

func TestServeSendsRegisterWithBindingsAndStopsOnEOF(t *testing.T) {
	f := newFakeBidiStream()
	c := New(Config{TenantID: "org-1", AgentID: "agent-a", MaxSessions: 3, Targets: []Target{{DBType: "postgres", DatabaseName: "app"}}}, slog.New(slog.NewTextHandler(io.Discard, nil)))

	errc := make(chan error, 1)
	go func() { errc <- c.serve(context.Background(), fakeGatewayClient{connectStream: f}, false) }()

	reg := drainRegister(t, f)
	if reg.GetTenantId() != "org-1" || reg.GetAgentId() != "agent-a" || reg.GetMaxSessions() != 3 {
		t.Fatalf("unexpected register: %+v", reg)
	}
	if len(reg.GetTargets()) != 1 || reg.GetTargets()[0].GetDbType() != "postgres" {
		t.Fatalf("unexpected target bindings: %+v", reg.GetTargets())
	}

	close(f.recvCh) // Recv() returns io.EOF
	select {
	case err := <-errc:
		if err != nil {
			t.Fatalf("expected serve to return nil on clean EOF, got %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("serve did not return after EOF")
	}
}

func TestServePropagatesNonEOFRecvError(t *testing.T) {
	f := newFakeBidiStream()
	f.recvErr = errors.New("connection reset")
	c := New(Config{TenantID: "org-1"}, slog.New(slog.NewTextHandler(io.Discard, nil)))

	errc := make(chan error, 1)
	go func() { errc <- c.serve(context.Background(), fakeGatewayClient{connectStream: f}, false) }()
	drainRegister(t, f)
	f.closeStream()

	select {
	case err := <-errc:
		if err == nil {
			t.Fatal("expected the recv error to propagate")
		}
	case <-time.After(2 * time.Second):
		t.Fatal("serve did not return after the recv error")
	}
}

func TestServeRespondsToPingWithHeartbeat(t *testing.T) {
	f := newFakeBidiStream()
	c := New(Config{TenantID: "org-1"}, slog.New(slog.NewTextHandler(io.Discard, nil)))
	go func() { _ = c.serve(context.Background(), fakeGatewayClient{connectStream: f}, false) }()
	drainRegister(t, f)

	f.recvCh <- &studiov1.GatewayMessage{Msg: &studiov1.GatewayMessage_Ping{Ping: &studiov1.Ping{}}}
	select {
	case m := <-f.sendCh:
		if m.GetHeartbeat() == nil {
			t.Fatalf("expected a heartbeat reply to Ping, got %+v", m)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for the heartbeat reply")
	}
	f.closeStream()
}

func TestStartAssignmentRejectsWhenAtCapacity(t *testing.T) {
	f := newFakeBidiStream()
	c := New(Config{MaxSessions: 1}, slog.New(slog.NewTextHandler(io.Discard, nil)))
	ss := &safeStream{stream: f}
	c.runs["already-running"] = func() {}

	c.startAssignment(context.Background(), ss, &studiov1.ExecuteAssignment{SessionId: "new-session"})
	select {
	case m := <-f.sendCh:
		ack := m.GetSessionAck()
		if ack == nil || ack.GetAccepted() || ack.GetReason() != "agent_at_capacity" {
			t.Fatalf("expected a capacity-rejection ack, got %+v", m)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for the capacity ack")
	}
}

func TestStartAssignmentIgnoresEmptySessionID(t *testing.T) {
	f := newFakeBidiStream()
	c := New(Config{MaxSessions: 5}, slog.New(slog.NewTextHandler(io.Discard, nil)))
	ss := &safeStream{stream: f}
	c.startAssignment(context.Background(), ss, &studiov1.ExecuteAssignment{SessionId: ""})
	select {
	case m := <-f.sendCh:
		t.Fatalf("expected no message for an empty session id, got %+v", m)
	case <-time.After(100 * time.Millisecond):
	}
}

func TestStartAssignmentIgnoresDuplicateSessionID(t *testing.T) {
	f := newFakeBidiStream()
	c := New(Config{MaxSessions: 5}, slog.New(slog.NewTextHandler(io.Discard, nil)))
	c.runs["dup"] = func() {}
	before := c.activeSessions()

	ss := &safeStream{stream: f}
	c.startAssignment(context.Background(), ss, &studiov1.ExecuteAssignment{SessionId: "dup", Request: &studiov1.ExecuteRequest{DryRun: true}})
	time.Sleep(50 * time.Millisecond)
	if c.activeSessions() != before {
		t.Fatalf("expected no new session to be tracked for a duplicate id, got %d sessions", c.activeSessions())
	}
}

func TestStartAssignmentDryRunEmitsFinishedWithoutExecuting(t *testing.T) {
	f := newFakeBidiStream()
	c := New(Config{MaxSessions: 5}, slog.New(slog.NewTextHandler(io.Discard, nil)))
	ss := &safeStream{stream: f}

	c.startAssignment(context.Background(), ss, &studiov1.ExecuteAssignment{
		SessionId: "s1",
		Request:   &studiov1.ExecuteRequest{DryRun: true},
	})

	var sawAck, sawStarted, sawFinished bool
	deadline := time.After(2 * time.Second)
	for !sawFinished {
		select {
		case m := <-f.sendCh:
			if m.GetSessionAck() != nil {
				sawAck = true
			}
			if ev := m.GetSessionEvent(); ev != nil {
				if ev.GetEvent().GetStarted() != nil {
					sawStarted = true
				}
				if fin := ev.GetEvent().GetFinished(); fin != nil {
					sawFinished = true
					var payload map[string]any
					if err := json.Unmarshal([]byte(fin.GetResponseJson()), &payload); err != nil {
						t.Fatal(err)
					}
					if payload["status"] != "dry_run" {
						t.Fatalf("expected dry_run status, got %v", payload)
					}
				}
			}
		case <-deadline:
			t.Fatalf("timed out: ack=%v started=%v finished=%v", sawAck, sawStarted, sawFinished)
		}
	}
	if !sawAck || !sawStarted {
		t.Fatalf("expected ack and started events too: ack=%v started=%v", sawAck, sawStarted)
	}
}

func TestStartAssignmentExecuteErrorEmitsErrorEvent(t *testing.T) {
	f := newFakeBidiStream()
	c := New(Config{MaxSessions: 5, Targets: nil}, slog.New(slog.NewTextHandler(io.Discard, nil)))
	ss := &safeStream{stream: f}

	c.startAssignment(context.Background(), ss, &studiov1.ExecuteAssignment{
		SessionId: "s2",
		Request:   &studiov1.ExecuteRequest{DbType: "postgres", DatabaseName: "nope", QueryContent: "SELECT 1"},
	})

	deadline := time.After(2 * time.Second)
	for {
		select {
		case m := <-f.sendCh:
			if ev := m.GetSessionEvent(); ev != nil {
				if errEv := ev.GetEvent().GetError(); errEv != nil {
					if errEv.GetCode() != "execute_error" {
						t.Fatalf("expected execute_error code, got %+v", errEv)
					}
					return
				}
			}
		case <-deadline:
			t.Fatal("timed out waiting for an error event")
		}
	}
}

func TestCancelSessionCancelsTrackedRun(t *testing.T) {
	c := New(Config{}, slog.New(slog.NewTextHandler(io.Discard, nil)))
	cancelled := false
	c.runs["s1"] = func() { cancelled = true }
	c.cancelSession("s1")
	if !cancelled {
		t.Fatal("expected the tracked cancel func to be invoked")
	}
}

func TestCancelSessionNoopForUnknownID(t *testing.T) {
	c := New(Config{}, slog.New(slog.NewTextHandler(io.Discard, nil)))
	c.cancelSession("does-not-exist") // must not panic
}

func TestFinishSessionRemovesTrackedRun(t *testing.T) {
	c := New(Config{}, slog.New(slog.NewTextHandler(io.Discard, nil)))
	cancelled := false
	c.runs["s1"] = func() { cancelled = true }
	c.finishSession("s1")
	if !cancelled {
		t.Fatal("expected finishSession to invoke the cancel func")
	}
	if c.activeSessions() != 0 {
		t.Fatalf("expected the run to be removed, got %d active sessions", c.activeSessions())
	}
}

func TestExecuteLocallyNoTargetBindingErrors(t *testing.T) {
	c := New(Config{}, slog.New(slog.NewTextHandler(io.Discard, nil)))
	_, err := c.executeLocally(context.Background(), &studiov1.ExecuteRequest{DbType: "postgres", DatabaseName: "app"})
	if err == nil {
		t.Fatal("expected an error when no local target binding matches")
	}
}

func TestExecuteLocallyDefaultsDBTypeToPostgres(t *testing.T) {
	c := New(Config{}, slog.New(slog.NewTextHandler(io.Discard, nil)))
	_, err := c.executeLocally(context.Background(), &studiov1.ExecuteRequest{DatabaseName: "app"})
	if err == nil {
		t.Fatal("expected an error (still no target binding), confirming the postgres default path ran")
	}
}

func TestNewAppliesDefaults(t *testing.T) {
	c := New(Config{}, nil)
	if c.cfg.MaxBackoff != 30*time.Second {
		t.Fatalf("expected default MaxBackoff, got %v", c.cfg.MaxBackoff)
	}
	if c.cfg.AgentID != "studio-agent" {
		t.Fatalf("expected default AgentID, got %q", c.cfg.AgentID)
	}
	if c.cfg.MaxSessions != 8 {
		t.Fatalf("expected default MaxSessions, got %d", c.cfg.MaxSessions)
	}
}

func TestNewPreservesExplicitConfig(t *testing.T) {
	c := New(Config{MaxBackoff: time.Minute, AgentID: "a1", MaxSessions: 2}, nil)
	if c.cfg.MaxBackoff != time.Minute || c.cfg.AgentID != "a1" || c.cfg.MaxSessions != 2 {
		t.Fatalf("expected explicit config preserved, got %+v", c.cfg)
	}
}

// fakeGatewayClient implements studiov1.StudioGatewayClient, returning a pre-built stream from
// Connect so serve() can be driven without a real network connection.
type fakeGatewayClient struct {
	connectStream *fakeBidiStream
}

func (f fakeGatewayClient) Connect(context.Context, ...grpc.CallOption) (grpc.BidiStreamingClient[studiov1.AgentMessage, studiov1.GatewayMessage], error) {
	return f.connectStream, nil
}

func (f fakeGatewayClient) Enroll(context.Context, *studiov1.EnrollRequest, ...grpc.CallOption) (*studiov1.EnrollResponse, error) {
	return nil, errors.New("not implemented in fake")
}

func TestHeartbeatLoopStopsOnContextCancel(t *testing.T) {
	c := New(Config{}, slog.New(slog.NewTextHandler(io.Discard, nil)))
	ss := &safeStream{stream: newFakeBidiStream()}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		c.heartbeatLoop(ctx, ss)
		close(done)
	}()
	cancel()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("heartbeatLoop did not stop after context cancellation")
	}
}
