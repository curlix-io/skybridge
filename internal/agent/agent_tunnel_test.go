package agent

import (
	"bytes"
	"context"
	"errors"
	"io"
	"log"
	"net"
	"testing"
	"time"

	"github.com/curlix-io/skybridge/internal/config"
	"github.com/curlix-io/skybridge/internal/mask"
	"github.com/curlix-io/skybridge/internal/tunnel"
)

// fakeDialer returns a stub Dial func that hands back one end of an in-memory pipe, recording the
// address it was asked to dial and signaling dialed once it has. The other end is drained so writes
// from the agent don't block.
func fakeDialer(gotAddr *string, dialed chan<- struct{}) func(context.Context, string, string) (net.Conn, error) {
	return func(_ context.Context, _ string, addr string) (net.Conn, error) {
		*gotAddr = addr
		agentSide, upstreamSide := net.Pipe()
		go func() { _, _ = io.Copy(io.Discard, upstreamSide) }()
		close(dialed)
		return agentSide, nil
	}
}

func TestServeTunnelConnRejectsRegistrationFailure(t *testing.T) {
	agentEnd, gatewayEnd := net.Pipe()
	defer agentEnd.Close()
	defer gatewayEnd.Close()

	gwSess := tunnel.Server(gatewayEnd)
	defer gwSess.Close()
	go func() {
		if _, err := gwSess.NextControl(); err == nil {
			_ = gwSess.SendControl(tunnel.Control{Kind: tunnel.KindRegisterAck, OK: false, Error: "bad token"})
		}
	}()

	err := ServeTunnelConn(context.Background(), agentEnd, config.Agent{AgentID: "a1", OrgID: "org-1", Token: "bad"}, Deps{}, nil)
	if err == nil {
		t.Fatal("expected registration rejection to surface as an error")
	}
}

func TestServeTunnelConnServesOneStream(t *testing.T) {
	agentEnd, gatewayEnd := net.Pipe()
	defer agentEnd.Close()

	gwSess := tunnel.Server(gatewayEnd)
	var gotAddr string
	dialed := make(chan struct{})

	go func() {
		ctrl, err := gwSess.NextControl()
		if err != nil {
			return
		}
		if ctrl.Kind != tunnel.KindRegister || ctrl.AgentID != "a1" {
			_ = gwSess.SendControl(tunnel.Control{Kind: tunnel.KindRegisterAck, OK: false, Error: "unexpected control"})
			return
		}
		if err := gwSess.SendControl(tunnel.Control{Kind: tunnel.KindRegisterAck, OK: true}); err != nil {
			return
		}
		st, err := gwSess.Open(tunnel.OpenMeta{Target: "prod", Addr: "db.internal:5432", DBType: "postgres"}.Encode())
		if err != nil {
			return
		}
		<-dialed
		_ = st.Close()
		_ = gwSess.Close()
	}()

	deps := Deps{Dial: fakeDialer(&gotAddr, dialed), Masker: mask.Noop{}}
	err := ServeTunnelConn(context.Background(), agentEnd, config.Agent{AgentID: "a1", OrgID: "org-1", Token: "t"}, deps, log.New(io.Discard, "", 0))

	if err != nil && !errors.Is(err, io.EOF) {
		t.Logf("ServeTunnelConn ended: %v", err)
	}
	if gotAddr != "db.internal:5432" {
		t.Fatalf("expected dial to db.internal:5432, got %q", gotAddr)
	}
}

func TestServeStreamSkipsOnBadMeta(t *testing.T) {
	clientEnd, serverEnd := net.Pipe()
	defer clientEnd.Close()
	defer serverEnd.Close()
	clientSess := tunnel.Client(clientEnd)
	defer clientSess.Close()
	serverSess := tunnel.Server(serverEnd)
	defer serverSess.Close()

	if _, err := clientSess.Open([]byte("not json")); err != nil {
		t.Fatalf("open: %v", err)
	}
	st, err := serverSess.Accept()
	if err != nil {
		t.Fatalf("accept: %v", err)
	}

	dialCalled := false
	deps := Deps{Dial: func(context.Context, string, string) (net.Conn, error) {
		dialCalled = true
		return nil, nil
	}}.withDefaults(config.Agent{})

	var buf bytes.Buffer
	serveStream(context.Background(), st, serverSess, config.Agent{}, deps, log.New(&buf, "", 0))
	if dialCalled {
		t.Fatal("expected serveStream to bail out before dialing on bad meta")
	}
	if !bytes.Contains(buf.Bytes(), []byte("bad meta")) {
		t.Fatalf("expected a bad-meta log, got %q", buf.String())
	}
}

func TestServeStreamLogsUnsupportedDBType(t *testing.T) {
	clientEnd, serverEnd := net.Pipe()
	defer clientEnd.Close()
	defer serverEnd.Close()
	clientSess := tunnel.Client(clientEnd)
	defer clientSess.Close()
	serverSess := tunnel.Server(serverEnd)
	defer serverSess.Close()

	if _, err := clientSess.Open(tunnel.OpenMeta{Target: "prod", Addr: "db:1", DBType: "oracle"}.Encode()); err != nil {
		t.Fatalf("open: %v", err)
	}
	st, err := serverSess.Accept()
	if err != nil {
		t.Fatalf("accept: %v", err)
	}
	deps := Deps{}.withDefaults(config.Agent{})
	var buf bytes.Buffer
	serveStream(context.Background(), st, serverSess, config.Agent{}, deps, log.New(&buf, "", 0))
	if !bytes.Contains(buf.Bytes(), []byte("stream open:")) {
		t.Fatalf("expected an unsupported-db-type log, got %q", buf.String())
	}
}

func TestServeStreamLogsUpstreamDialFailure(t *testing.T) {
	clientEnd, serverEnd := net.Pipe()
	defer clientEnd.Close()
	defer serverEnd.Close()
	clientSess := tunnel.Client(clientEnd)
	defer clientSess.Close()
	serverSess := tunnel.Server(serverEnd)
	defer serverSess.Close()

	if _, err := clientSess.Open(tunnel.OpenMeta{Target: "prod", Addr: "db.internal:5432", DBType: "postgres"}.Encode()); err != nil {
		t.Fatalf("open: %v", err)
	}
	st, err := serverSess.Accept()
	if err != nil {
		t.Fatalf("accept: %v", err)
	}
	deps := Deps{Dial: func(context.Context, string, string) (net.Conn, error) {
		return nil, errors.New("connection refused")
	}}.withDefaults(config.Agent{})
	var buf bytes.Buffer
	serveStream(context.Background(), st, serverSess, config.Agent{}, deps, log.New(&buf, "", 0))
	if !bytes.Contains(buf.Bytes(), []byte("dial upstream")) {
		t.Fatalf("expected a dial-failure log, got %q", buf.String())
	}
}

func TestServeStreamLogsUpstreamTLSFailure(t *testing.T) {
	clientEnd, serverEnd := net.Pipe()
	defer clientEnd.Close()
	defer serverEnd.Close()
	clientSess := tunnel.Client(clientEnd)
	defer clientSess.Close()
	serverSess := tunnel.Server(serverEnd)
	defer serverSess.Close()

	if _, err := clientSess.Open(tunnel.OpenMeta{Target: "prod", Addr: "db.internal:5432", DBType: "postgres"}.Encode()); err != nil {
		t.Fatalf("open: %v", err)
	}
	st, err := serverSess.Accept()
	if err != nil {
		t.Fatalf("accept: %v", err)
	}
	upTLS := &upstreamTLSPolicy{mode: "require"}
	deps := Deps{Dial: func(context.Context, string, string) (net.Conn, error) {
		a, b := net.Pipe()
		go b.Close() // upstream closes immediately, failing the TLS handshake
		return a, nil
	}, UpstreamTLS: upTLS}.withDefaults(config.Agent{})
	var buf bytes.Buffer
	serveStream(context.Background(), st, serverSess, config.Agent{}, deps, log.New(&buf, "", 0))
	if !bytes.Contains(buf.Bytes(), []byte("upstream TLS to")) {
		t.Fatalf("expected an upstream-TLS-failure log, got %q", buf.String())
	}
}

func TestServeStreamSkipsWhenMetaMissingAddrOrDBType(t *testing.T) {
	clientEnd, serverEnd := net.Pipe()
	defer clientEnd.Close()
	defer serverEnd.Close()
	clientSess := tunnel.Client(clientEnd)
	defer clientSess.Close()
	serverSess := tunnel.Server(serverEnd)
	defer serverSess.Close()

	if _, err := clientSess.Open(tunnel.OpenMeta{Target: "prod"}.Encode()); err != nil {
		t.Fatalf("open: %v", err)
	}
	st, err := serverSess.Accept()
	if err != nil {
		t.Fatalf("accept: %v", err)
	}

	dialCalled := false
	deps := Deps{Dial: func(context.Context, string, string) (net.Conn, error) {
		dialCalled = true
		return nil, nil
	}}.withDefaults(config.Agent{})

	serveStream(context.Background(), st, serverSess, config.Agent{}, deps, log.New(io.Discard, "", 0))
	if dialCalled {
		t.Fatal("expected serveStream to bail out before dialing when addr/db_type are empty")
	}
}

func TestHeartbeatLoopStopsOnContextCancel(t *testing.T) {
	agentEnd, peerEnd := net.Pipe()
	defer agentEnd.Close()
	defer peerEnd.Close()
	sess := tunnel.Client(agentEnd)
	defer sess.Close()

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		heartbeatLoop(ctx, sess)
		close(done)
	}()
	cancel()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("heartbeatLoop did not stop after context cancellation")
	}
}

func TestHeartbeatLoopStopsOnSessionClosed(t *testing.T) {
	agentEnd, peerEnd := net.Pipe()
	defer peerEnd.Close()
	sess := tunnel.Client(agentEnd)

	done := make(chan struct{})
	go func() {
		heartbeatLoop(context.Background(), sess)
		close(done)
	}()
	_ = sess.Close()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("heartbeatLoop did not stop after session closed")
	}
}
