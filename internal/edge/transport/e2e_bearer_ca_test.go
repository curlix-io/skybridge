package transport

import (
	"context"
	"io"
	"log/slog"
	"testing"
	"time"

	connectorv1 "github.com/curlix-io/skybridge/internal/genpb/curlix/connector/v1"

	"github.com/curlix-io/skybridge/internal/edge"
)

// fakeRegisterOnlyGateway records the first Register it receives on a real (non-bufconn) TLS
// listener, then keeps the stream open until the client disconnects.
type fakeRegisterOnlyGateway struct {
	connectorv1.UnimplementedConnectorGatewayServer
	gotReg chan *connectorv1.Register
}

func (g *fakeRegisterOnlyGateway) Connect(stream connectorv1.ConnectorGateway_ConnectServer) error {
	first, err := stream.Recv()
	if err != nil {
		return err
	}
	reg := first.GetRegister()
	if reg == nil {
		return nil
	}
	select {
	case g.gotReg <- reg:
	default:
	}
	if err := stream.Send(&connectorv1.GatewayMessage{
		Msg: &connectorv1.GatewayMessage_Registered{Registered: &connectorv1.Registered{SessionId: "sess-1"}},
	}); err != nil {
		return err
	}
	for {
		if _, err := stream.Recv(); err != nil {
			return nil
		}
	}
}

// TestRunCompletesRegisterOverBearerWithPrivateCA is the end-to-end regression test for the bug
// class fixed alongside this test: bearer mode (SKYBRIDGE_CONNECTOR_KEY set, ForceBearer=true)
// must actually complete registration against a gateway whose TLS cert is signed by a private CA
// — not merely build TLS credentials that look plausible in isolation.
// TestDialWithForceBearerAndCABundleTrustsPrivateCA only proves dial() constructs a working
// *grpc.ClientConn; it never proved the resulting connection could complete a real handshake
// against an actual TLS listener. That gap is exactly how the underlying bug (bearer mode
// silently falling back to system roots and failing every dial with "x509: certificate signed by
// unknown authority" against a private CA) went unnoticed: every other Run()/serve() test in this
// package dials over bufconn with insecure.NewCredentials(), which never exercises TLS
// verification at all. This test uses a real net.Listen TCP socket wrapped in TLS (via
// startTLSGRPCServer, from material_test.go) precisely to close that gap.
func TestRunCompletesRegisterOverBearerWithPrivateCA(t *testing.T) {
	ca := newTestCA(t)
	fake := &fakeRegisterOnlyGateway{gotReg: make(chan *connectorv1.Register, 1)}
	target, stop := startTLSGRPCServer(t, ca, fake)
	defer stop()

	c := New(Config{
		Target:      target,
		TenantID:    "org-1",
		ConnectorID: "edge-1",
		Token:       "reusable-bearer-token",
		ForceBearer: true,
		CABundlePEM: ca.certPEM,
		Reconnect:   false,
	}, edge.NewRegistry(), slog.New(slog.NewTextHandler(io.Discard, nil)))

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	done := make(chan error, 1)
	go func() { done <- c.Run(ctx) }()

	select {
	case reg := <-fake.gotReg:
		if reg.GetTenantId() != "org-1" || reg.GetConnectorId() != "edge-1" {
			t.Fatalf("unexpected Register: %+v", reg)
		}
	case <-time.After(4 * time.Second):
		t.Fatal("gateway never received Register — bearer mode failed to complete the TLS handshake against the private CA")
	}
	cancel()
	<-done
}

// TestRunFailsWithoutCABundleAgainstPrivateCAGateway is the inverse of the above: bearer mode
// with NO CABundlePEM configured must fail against a private-CA gateway (falling back to system
// roots, which don't trust it) — pinning the pre-fix behavior as a still-correct failure mode for
// a genuinely unconfigured deployment, so a future change can't accidentally make bearer mode
// trust an arbitrary/unspecified CA by default.
func TestRunFailsWithoutCABundleAgainstPrivateCAGateway(t *testing.T) {
	ca := newTestCA(t)
	fake := &fakeRegisterOnlyGateway{gotReg: make(chan *connectorv1.Register, 1)}
	target, stop := startTLSGRPCServer(t, ca, fake)
	defer stop()

	c := New(Config{
		Target:      target,
		TenantID:    "org-1",
		ConnectorID: "edge-1",
		Token:       "reusable-bearer-token",
		ForceBearer: true,
		// CABundlePEM intentionally unset.
		Reconnect: false,
	}, edge.NewRegistry(), slog.New(slog.NewTextHandler(io.Discard, nil)))

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	done := make(chan error, 1)
	go func() { done <- c.Run(ctx) }()

	select {
	case reg := <-fake.gotReg:
		t.Fatalf("expected registration to fail without a trusted CA, but gateway received Register: %+v", reg)
	case <-time.After(1500 * time.Millisecond):
		// expected: no registration within the window
	}
	cancel()
	<-done
}
