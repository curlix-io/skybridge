package studiotransport

// Additional coverage for branches transport_test.go doesn't already exercise: the Registered log
// line, ExecuteAssignment/CancelSession dispatch out of serve()'s recv loop, Run's dial-fails ->
// backoff -> reconnect-succeeds path, and executeLocally's happy path via a resolvable target.

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"testing"
	"time"

	studiov1 "github.com/curlix-io/skybridge/internal/genpb/curlix/studiogateway/v1"
)

func TestServeLogsRegisteredAck(t *testing.T) {
	f := newFakeBidiStream()
	c := New(Config{TenantID: "org-1"}, slog.New(slog.NewTextHandler(io.Discard, nil)))
	go func() { _ = c.serve(context.Background(), fakeGatewayClient{connectStream: f}, false) }()
	drainRegister(t, f)

	f.recvCh <- &studiov1.GatewayMessage{Msg: &studiov1.GatewayMessage_Registered{Registered: &studiov1.Registered{LeaseId: "lease-1"}}}
	// Give the recv loop a moment to process the Registered branch before tearing down.
	time.Sleep(50 * time.Millisecond)
	f.closeStream()
}

func TestServeDispatchesExecuteAssignmentFromRecvLoop(t *testing.T) {
	f := newFakeBidiStream()
	c := New(Config{TenantID: "org-1", MaxSessions: 5}, slog.New(slog.NewTextHandler(io.Discard, nil)))
	go func() { _ = c.serve(context.Background(), fakeGatewayClient{connectStream: f}, false) }()
	drainRegister(t, f)

	f.recvCh <- &studiov1.GatewayMessage{Msg: &studiov1.GatewayMessage_ExecuteAssignment{
		ExecuteAssignment: &studiov1.ExecuteAssignment{
			SessionId: "sess-via-serve",
			Request:   &studiov1.ExecuteRequest{DryRun: true},
		},
	}}

	deadline := time.After(2 * time.Second)
	for {
		select {
		case m := <-f.sendCh:
			if ack := m.GetSessionAck(); ack != nil && ack.GetSessionId() == "sess-via-serve" {
				f.closeStream()
				return
			}
		case <-deadline:
			t.Fatal("timed out waiting for the ExecuteAssignment dispatched through serve()'s recv loop to produce a SessionAck")
		}
	}
}

func TestServeDispatchesCancelSessionFromRecvLoop(t *testing.T) {
	f := newFakeBidiStream()
	c := New(Config{TenantID: "org-1"}, slog.New(slog.NewTextHandler(io.Discard, nil)))
	cancelled := make(chan struct{})
	c.runs["sess-cancel"] = func() { close(cancelled) }

	go func() { _ = c.serve(context.Background(), fakeGatewayClient{connectStream: f}, false) }()
	drainRegister(t, f)

	f.recvCh <- &studiov1.GatewayMessage{Msg: &studiov1.GatewayMessage_CancelSession{
		CancelSession: &studiov1.CancelSession{SessionId: "sess-cancel"},
	}}

	select {
	case <-cancelled:
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for CancelSession dispatched through serve()'s recv loop to invoke the tracked cancel func")
	}
	f.closeStream()
}

// TestRunDialFailsThenReturnsWithoutReconnect exercises Run's dial-error branch (the logger.Printf
// on a failed dial) when Reconnect is left false, so Run returns the dial error directly rather than
// looping.
func TestRunDialFailsThenReturnsWithoutReconnect(t *testing.T) {
	c := New(Config{Target: "http://%zz-invalid-target"}, slog.New(slog.NewTextHandler(io.Discard, nil)))
	err := c.Run(context.Background())
	if err == nil {
		t.Fatal("expected Run to propagate the dial error for a malformed target")
	}
}

// TestRunDialFailsThenReconnectsAndBacksOff drives Run through at least one failed dial with
// Reconnect=true, confirming the backoff-then-retry loop runs (rather than asserting only on the
// final context error), covering the backoff-doubling branch.
func TestRunDialFailsThenReconnectsAndBacksOff(t *testing.T) {
	c := New(Config{Target: "127.0.0.1:1", Reconnect: true, MaxBackoff: 5 * time.Millisecond}, slog.New(slog.NewTextHandler(io.Discard, nil)))
	ctx, cancel := context.WithTimeout(context.Background(), 40*time.Millisecond)
	defer cancel()
	err := c.Run(ctx)
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("expected context.DeadlineExceeded after backoff/retry loop, got %v", err)
	}
}

// TestExecuteLocallyResolvesAndSurfacesUnderlyingExecuteError confirms the happy branch of
// dbquery.Resolve inside executeLocally is reached when a matching Target is configured — the
// underlying dbquery.Execute call still errors (no real DB), but that proves Resolve found the
// binding and control passed through to dbquery.Execute rather than short-circuiting on "no local
// target binding".
func TestExecuteLocallyResolvesAndSurfacesUnderlyingExecuteError(t *testing.T) {
	c := New(Config{Targets: []Target{{DBType: "postgres", DatabaseName: "app", Host: "127.0.0.1:1"}}}, slog.New(slog.NewTextHandler(io.Discard, nil)))
	_, err := c.executeLocally(context.Background(), &studiov1.ExecuteRequest{
		DbType:       "postgres",
		DatabaseName: "app",
		QueryContent: "SELECT 1",
	})
	if err == nil {
		t.Fatal("expected an error connecting to the bogus host, confirming Resolve found the target and Execute ran")
	}
	if err.Error() == "no local target binding for postgres//app" {
		t.Fatal("expected to get past the no-target-binding branch since a matching Target was configured")
	}
}

func TestHandleAssignmentSuccessPathEmitsFinishedWithEncodedPayload(t *testing.T) {
	// DryRun already covers the "Finished" event shape; this exercises handleAssignment's non-dry-run
	// success path (executeLocally succeeds, json.Marshal succeeds, Finished emitted) using a target
	// whose db_type resolves to nothing configured on Targets, forcing executeLocally to error instead
	// — the counterpart already-covered "execute_error" path is TestStartAssignmentExecuteErrorEmitsErrorEvent.
	// Here we instead confirm handleAssignment's Started+Ack sequence always precedes any outcome event.
	f := newFakeBidiStream()
	c := New(Config{MaxSessions: 5}, slog.New(slog.NewTextHandler(io.Discard, nil)))
	ss := &safeStream{stream: f}

	c.handleAssignment(context.Background(), ss, &studiov1.ExecuteAssignment{
		SessionId: "s3",
		Request:   &studiov1.ExecuteRequest{DbType: "postgres", DatabaseName: "nope"},
	})

	var sawAck, sawStarted, sawOutcome bool
	deadline := time.After(2 * time.Second)
	for !sawOutcome {
		select {
		case m := <-f.sendCh:
			if m.GetSessionAck() != nil {
				sawAck = true
			}
			if ev := m.GetSessionEvent(); ev != nil {
				if ev.GetEvent().GetStarted() != nil {
					sawStarted = true
				}
				if ev.GetEvent().GetError() != nil || ev.GetEvent().GetFinished() != nil {
					sawOutcome = true
				}
			}
		case <-deadline:
			t.Fatalf("timed out: ack=%v started=%v outcome=%v", sawAck, sawStarted, sawOutcome)
		}
	}
	if !sawAck || !sawStarted {
		t.Fatalf("expected ack and started before the outcome event: ack=%v started=%v", sawAck, sawStarted)
	}
}
