package agent

import (
	"bytes"
	"context"
	"crypto/tls"
	"io"
	"log/slog"
	"net"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/curlix-io/skybridge/internal/config"
	"github.com/curlix-io/skybridge/internal/tunnel"
)

// syncBuffer is a mutex-guarded bytes.Buffer for tests that poll a *log.Logger's output from the
// test goroutine while a background goroutine (e.g. RunListener's per-connection session goroutine)
// concurrently writes to the same logger — a bare bytes.Buffer would race under -race.
type syncBuffer struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (b *syncBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.Write(p)
}

func (b *syncBuffer) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.String()
}

// freeTCPAddr reserves an ephemeral local port and immediately releases it, returning the address
// string for a caller (like RunListener) that wants to bind it itself moments later. Racy in
// theory, but the same pattern used across this repo's own listener tests (e.g.
// internal/gateway/gateway_internal_test.go) when the code under test owns the net.Listen call.
func freeTCPAddr(t *testing.T) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := ln.Addr().String()
	_ = ln.Close()
	return addr
}

// TestRunListenerProxiesConnection drives RunListener end-to-end over real TCP: a fake upstream
// "database" listener accepts and immediately closes each connection, and a native client dials the
// agent's listen address. This exercises the accept loop, upstream dial, and the mongodb engine's
// Proxy dispatch (chosen because it needs no wire handshake to start relaying, unlike Postgres).
func TestRunListenerProxiesConnection(t *testing.T) {
	upstreamLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer upstreamLn.Close()
	accepted := make(chan struct{}, 1)
	go func() {
		for {
			c, err := upstreamLn.Accept()
			if err != nil {
				return
			}
			accepted <- struct{}{}
			_ = c.Close()
		}
	}()

	listenAddr := freeTCPAddr(t)
	cfg := config.Agent{
		DBType:       "mongodb",
		ListenAddr:   listenAddr,
		UpstreamAddr: upstreamLn.Addr().String(),
	}

	ctx, cancel := context.WithCancel(context.Background())
	errc := make(chan error, 1)
	go func() { errc <- RunListener(ctx, cfg, slog.New(slog.NewTextHandler(io.Discard, nil))) }()

	// Give the listener a moment to bind before dialing.
	var client net.Conn
	for i := 0; i < 50; i++ {
		client, err = net.Dial("tcp", listenAddr)
		if err == nil {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	if err != nil {
		cancel()
		t.Fatalf("dial listener: %v", err)
	}
	defer client.Close()

	select {
	case <-accepted:
	case <-time.After(3 * time.Second):
		t.Fatal("upstream never saw a connection from the agent")
	}

	cancel()
	select {
	case err := <-errc:
		if err != nil {
			t.Fatalf("expected RunListener to return nil on ctx cancellation, got %v", err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("RunListener did not stop after ctx cancellation")
	}
}

// TestRunListenerLogsUpstreamDialFailure drives the accept loop's dial-failure branch: the upstream
// address is unreachable (connection refused), so the session goroutine must log and return without
// panicking, and RunListener itself must still stop cleanly on ctx cancellation.
func TestRunListenerLogsUpstreamDialFailure(t *testing.T) {
	listenAddr := freeTCPAddr(t)
	buf := &syncBuffer{}
	cfg := config.Agent{
		DBType:       "mongodb",
		ListenAddr:   listenAddr,
		UpstreamAddr: "127.0.0.1:1",
	}
	ctx, cancel := context.WithCancel(context.Background())
	errc := make(chan error, 1)
	go func() { errc <- RunListener(ctx, cfg, slog.New(slog.NewTextHandler(buf, nil))) }()

	var client net.Conn
	var err error
	for i := 0; i < 50; i++ {
		client, err = net.Dial("tcp", listenAddr)
		if err == nil {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	if err != nil {
		cancel()
		t.Fatalf("dial listener: %v", err)
	}

	// Wait for the dial-failure log line, then close our end and stop the agent.
	deadline := time.Now().Add(3 * time.Second)
	for !strings.Contains(buf.String(), "dial upstream") && time.Now().Before(deadline) {
		time.Sleep(20 * time.Millisecond)
	}
	client.Close()
	cancel()
	select {
	case <-errc:
	case <-time.After(3 * time.Second):
		t.Fatal("RunListener did not stop after ctx cancellation")
	}
	if !strings.Contains(buf.String(), "dial upstream") {
		t.Fatalf("expected a dial-failure log, got %q", buf.String())
	}
}

// TestRunListenerLogsUpstreamTLSFailure drives the accept loop's upstream-TLS-failure branch: the
// agent is configured to require upstream TLS, but the upstream fake "database" never speaks TLS
// (it just accepts and reads, so the client's TLS handshake bytes go nowhere and the handshake
// eventually errors out on context cancellation / connection reset).
func TestRunListenerLogsUpstreamTLSFailure(t *testing.T) {
	upstreamLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer upstreamLn.Close()
	go func() {
		for {
			c, err := upstreamLn.Accept()
			if err != nil {
				return
			}
			// Accept but close immediately without ever completing a TLS handshake.
			_ = c.Close()
		}
	}()

	listenAddr := freeTCPAddr(t)
	buf := &syncBuffer{}
	cfg := config.Agent{
		DBType:          "mongodb",
		ListenAddr:      listenAddr,
		UpstreamAddr:    upstreamLn.Addr().String(),
		UpstreamTLSMode: "require",
	}
	ctx, cancel := context.WithCancel(context.Background())
	errc := make(chan error, 1)
	go func() { errc <- RunListener(ctx, cfg, slog.New(slog.NewTextHandler(buf, nil))) }()

	var client net.Conn
	for i := 0; i < 50; i++ {
		client, err = net.Dial("tcp", listenAddr)
		if err == nil {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	if err != nil {
		cancel()
		t.Fatalf("dial listener: %v", err)
	}

	deadline := time.Now().Add(3 * time.Second)
	for !strings.Contains(buf.String(), "upstream TLS to") && time.Now().Before(deadline) {
		time.Sleep(20 * time.Millisecond)
	}
	client.Close()
	cancel()
	select {
	case <-errc:
	case <-time.After(3 * time.Second):
		t.Fatal("RunListener did not stop after ctx cancellation")
	}
	if !strings.Contains(buf.String(), "upstream TLS to") {
		t.Fatalf("expected an upstream-TLS-failure log, got %q", buf.String())
	}
}

func TestRunListenerRejectsBadUpstreamTLSMode(t *testing.T) {
	cfg := config.Agent{
		DBType:          "mongodb",
		ListenAddr:      freeTCPAddr(t),
		UpstreamAddr:    "127.0.0.1:1",
		UpstreamTLSMode: "bogus",
	}
	if err := RunListener(context.Background(), cfg, slog.New(slog.NewTextHandler(io.Discard, nil))); err == nil {
		t.Fatal("expected an error for an invalid upstream TLS mode")
	}
}

func TestRunListenerRejectsBadClientTLSCertKeyPair(t *testing.T) {
	certPEM, _, err := selfSignedCertPEMForTest(t)
	if err != nil {
		t.Fatal(err)
	}
	_, keyPEM2, err := selfSignedCertPEMForTest(t)
	if err != nil {
		t.Fatal(err)
	}
	cfg := config.Agent{
		DBType:           "mongodb",
		ListenAddr:       freeTCPAddr(t),
		UpstreamAddr:     "127.0.0.1:1",
		ClientTLSCertPEM: certPEM,
		ClientTLSKeyPEM:  keyPEM2, // mismatched key
	}
	if err := RunListener(context.Background(), cfg, slog.New(slog.NewTextHandler(io.Discard, nil))); err == nil {
		t.Fatal("expected an error for a mismatched client TLS cert/key pair")
	}
}

func TestRunListenerRejectsBadPostgresCatalogDSN(t *testing.T) {
	cfg := config.Agent{
		DBType:             "postgres",
		ListenAddr:         freeTCPAddr(t),
		UpstreamAddr:       "127.0.0.1:1",
		PostgresCatalogDSN: "not-a-dsn",
	}
	if err := RunListener(context.Background(), cfg, slog.New(slog.NewTextHandler(io.Discard, nil))); err == nil {
		t.Fatal("expected an error for a malformed Postgres catalog DSN")
	}
}

// TestRunListenerWithPathLabelURLStartsStore drives RunListener with SKYBRIDGE_PATH_LABEL_URL set
// so buildMaskerWithOverlay returns a non-nil pathLabelStore, exercising its Start(ctx) call.
func TestRunListenerWithPathLabelURLStartsStore(t *testing.T) {
	upstreamLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer upstreamLn.Close()
	go func() {
		for {
			c, err := upstreamLn.Accept()
			if err != nil {
				return
			}
			_ = c.Close()
		}
	}()

	listenAddr := freeTCPAddr(t)
	cfg := config.Agent{
		DBType:       "mongodb",
		ListenAddr:   listenAddr,
		UpstreamAddr: upstreamLn.Addr().String(),
		PathLabelURL: "http://127.0.0.1:0/path-labels",
	}
	ctx, cancel := context.WithCancel(context.Background())
	errc := make(chan error, 1)
	go func() { errc <- RunListener(ctx, cfg, slog.New(slog.NewTextHandler(io.Discard, nil))) }()

	var client net.Conn
	for i := 0; i < 50; i++ {
		client, err = net.Dial("tcp", listenAddr)
		if err == nil {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	if err != nil {
		cancel()
		t.Fatalf("dial listener: %v", err)
	}
	client.Close()

	cancel()
	select {
	case <-errc:
	case <-time.After(3 * time.Second):
		t.Fatal("RunListener did not stop after ctx cancellation")
	}
}

func TestRunListenerRejectsUnsupportedDBType(t *testing.T) {
	cfg := config.Agent{
		DBType:       "oracle",
		ListenAddr:   freeTCPAddr(t),
		UpstreamAddr: "127.0.0.1:1",
	}
	if err := RunListener(context.Background(), cfg, slog.New(slog.NewTextHandler(io.Discard, nil))); err == nil {
		t.Fatal("expected an error for an unsupported db type")
	}
}

func TestRunListenerRejectsBadListenAddr(t *testing.T) {
	cfg := config.Agent{
		DBType:       "mongodb",
		ListenAddr:   "not-a-valid-address",
		UpstreamAddr: "127.0.0.1:1",
	}
	if err := RunListener(context.Background(), cfg, slog.New(slog.NewTextHandler(io.Discard, nil))); err == nil {
		t.Fatal("expected an error for an unbindable listen address")
	}
}

// TestRunTunnelDialsGatewayAndRegisters drives RunTunnel against a fake gateway server that accepts
// the TCP connection, completes tunnel registration, then closes — exercising the dial loop, the
// default Deps wiring (masker/engine/upstream-TLS built from cfg), and ServeTunnelConn's registration
// handshake, before RunTunnel reconnects (which we stop via ctx cancellation).
func TestRunTunnelDialsGatewayAndRegisters(t *testing.T) {
	gwLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer gwLn.Close()

	registered := make(chan struct{}, 1)
	go func() {
		for {
			conn, err := gwLn.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				sess := tunnel.Server(c)
				defer sess.Close()
				if _, err := sess.NextControl(); err != nil {
					return
				}
				_ = sess.SendControl(tunnel.Control{Kind: tunnel.KindRegisterAck, OK: true})
				select {
				case registered <- struct{}{}:
				default:
				}
			}(conn)
		}
	}()

	ctx, cancel := context.WithCancel(context.Background())
	cfg := config.Agent{
		AgentID:     "a1",
		OrgID:       "org-1",
		Token:       "t",
		GatewayAddr: gwLn.Addr().String(),
	}
	errc := make(chan error, 1)
	go func() { errc <- RunTunnel(ctx, cfg, Deps{}, slog.New(slog.NewTextHandler(io.Discard, nil))) }()

	select {
	case <-registered:
	case <-time.After(3 * time.Second):
		t.Fatal("gateway never saw a completed registration")
	}

	cancel()
	select {
	case err := <-errc:
		if err != nil {
			t.Fatalf("expected RunTunnel to return nil on ctx cancellation, got %v", err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("RunTunnel did not stop after ctx cancellation")
	}
}

// TestRunTunnelWithPathLabelURLStartsStore drives RunTunnel's default-masker branch (deps.Masker
// nil) with SKYBRIDGE_PATH_LABEL_URL set, so buildMaskerWithOverlay returns a non-nil
// pathLabelStore and RunTunnel's own pathLabelStore.Start(ctx) call runs.
func TestRunTunnelWithPathLabelURLStartsStore(t *testing.T) {
	gwLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer gwLn.Close()
	registered := make(chan struct{}, 1)
	go func() {
		for {
			conn, err := gwLn.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				sess := tunnel.Server(c)
				defer sess.Close()
				if _, err := sess.NextControl(); err != nil {
					return
				}
				_ = sess.SendControl(tunnel.Control{Kind: tunnel.KindRegisterAck, OK: true})
				select {
				case registered <- struct{}{}:
				default:
				}
			}(conn)
		}
	}()

	ctx, cancel := context.WithCancel(context.Background())
	cfg := config.Agent{
		AgentID:      "a1",
		OrgID:        "org-1",
		Token:        "t",
		GatewayAddr:  gwLn.Addr().String(),
		PathLabelURL: "http://127.0.0.1:0/path-labels",
	}
	errc := make(chan error, 1)
	go func() { errc <- RunTunnel(ctx, cfg, Deps{}, slog.New(slog.NewTextHandler(io.Discard, nil))) }()

	select {
	case <-registered:
	case <-time.After(3 * time.Second):
		t.Fatal("gateway never saw a completed registration")
	}
	cancel()
	select {
	case err := <-errc:
		if err != nil {
			t.Fatalf("expected RunTunnel to return nil on ctx cancellation, got %v", err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("RunTunnel did not stop after ctx cancellation")
	}
}

// TestRunTunnelRejectsBadClientTLSCertKeyPair drives RunTunnel's default-engine branch (deps.Engine
// nil) with a mismatched client TLS cert/key pair, which buildClientTLSConfig must reject before any
// gateway dial happens.
func TestRunTunnelRejectsBadClientTLSCertKeyPair(t *testing.T) {
	certPEM, _, err := selfSignedCertPEMForTest(t)
	if err != nil {
		t.Fatal(err)
	}
	_, keyPEM2, err := selfSignedCertPEMForTest(t)
	if err != nil {
		t.Fatal(err)
	}
	cfg := config.Agent{
		AgentID:          "a1",
		GatewayAddr:      "127.0.0.1:1",
		ClientTLSCertPEM: certPEM,
		ClientTLSKeyPEM:  keyPEM2, // mismatched key
	}
	if err := RunTunnel(context.Background(), cfg, Deps{}, slog.New(slog.NewTextHandler(io.Discard, nil))); err == nil {
		t.Fatal("expected an error for a mismatched client TLS cert/key pair")
	}
}

// TestRunTunnelRejectsBadPostgresCatalogDSN drives RunTunnel's default-engine branch with a
// malformed SKYBRIDGE_POSTGRES_CATALOG_DSN, which must be rejected before any gateway dial happens.
func TestRunTunnelRejectsBadPostgresCatalogDSN(t *testing.T) {
	cfg := config.Agent{
		AgentID:            "a1",
		GatewayAddr:        "127.0.0.1:1",
		PostgresCatalogDSN: "not-a-dsn",
	}
	if err := RunTunnel(context.Background(), cfg, Deps{}, slog.New(slog.NewTextHandler(io.Discard, nil))); err == nil {
		t.Fatal("expected an error for a malformed Postgres catalog DSN")
	}
}

// TestRunTunnelDefaultEngineWithClientTLSLogsEnabled drives RunTunnel's default-engine branch
// (deps.Engine nil) with client TLS configured, exercising the "client TLS termination ENABLED" log
// line and the Postgres catalog resolver's success path together.
func TestRunTunnelDefaultEngineWithClientTLSLogsEnabled(t *testing.T) {
	gwLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer gwLn.Close()
	registered := make(chan struct{}, 1)
	go func() {
		for {
			conn, err := gwLn.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				sess := tunnel.Server(c)
				defer sess.Close()
				if _, err := sess.NextControl(); err != nil {
					return
				}
				_ = sess.SendControl(tunnel.Control{Kind: tunnel.KindRegisterAck, OK: true})
				select {
				case registered <- struct{}{}:
				default:
				}
			}(conn)
		}
	}()

	ctx, cancel := context.WithCancel(context.Background())
	var buf bytes.Buffer
	cfg := config.Agent{
		AgentID:             "a1",
		OrgID:               "org-1",
		Token:               "t",
		GatewayAddr:         gwLn.Addr().String(),
		ClientTLSSelfSigned: true,
		PostgresCatalogDSN:  "postgres://db.internal:5432/postgres",
	}
	errc := make(chan error, 1)
	go func() { errc <- RunTunnel(ctx, cfg, Deps{}, slog.New(slog.NewTextHandler(&buf, nil))) }()

	select {
	case <-registered:
	case <-time.After(3 * time.Second):
		t.Fatal("gateway never saw a completed registration")
	}
	cancel()
	select {
	case err := <-errc:
		if err != nil {
			t.Fatalf("expected RunTunnel to return nil on ctx cancellation, got %v", err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("RunTunnel did not stop after ctx cancellation")
	}
	if !strings.Contains(buf.String(), "client TLS termination ENABLED for Postgres targets") {
		t.Fatalf("expected a client-TLS-enabled log, got %q", buf.String())
	}
}

// TestRunTunnelWireMtlsIamAuthLogsAndRetries drives the WireMtlsIamAuthEnabled branch of RunTunnel's
// wire-mTLS loop. Without real AWS credentials/network, EnsureMaterialViaIAM is expected to fail
// (either loading ambient credentials or presigning/calling out), which must log a retry warning and
// stop cleanly on ctx timeout rather than propagate as a RunTunnel error.
func TestRunTunnelWireMtlsIamAuthLogsAndRetries(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	var buf bytes.Buffer
	cfg := config.Agent{
		AgentID:                "a1",
		GatewayAddr:            "127.0.0.1:1",
		WireMtlsEnrollURL:      "http://127.0.0.1:1",
		WireMtlsIamAuthEnabled: true,
	}
	err := RunTunnel(ctx, cfg, Deps{}, slog.New(slog.NewTextHandler(&buf, nil)))
	if err != nil {
		t.Fatalf("expected RunTunnel to return nil on ctx timeout, got %v", err)
	}
	out := buf.String()
	if !strings.Contains(out, "wire mTLS via AWS IAM auth configured") {
		t.Fatalf("expected an IAM-auth-configured log, got %q", out)
	}
	if !strings.Contains(out, "wire mTLS IAM enroll") && !strings.Contains(out, "wire mTLS material invalid") {
		t.Fatalf("expected an IAM enroll retry or material-invalid log, got %q", out)
	}
}

func TestRunTunnelRejectsBadUpstreamTLSMode(t *testing.T) {
	cfg := config.Agent{
		AgentID:         "a1",
		GatewayAddr:     "127.0.0.1:1",
		UpstreamTLSMode: "bogus",
	}
	if err := RunTunnel(context.Background(), cfg, Deps{}, slog.New(slog.NewTextHandler(io.Discard, nil))); err == nil {
		t.Fatal("expected an error for an invalid upstream TLS mode")
	}
}

// TestRunTunnelInjectCredentialsWarnsWithoutExchangeURL drives RunTunnel's
// InjectCredentials-without-a-resolver branch by using a real dialer against an immediately-closing
// gateway listener, then cancels ctx after one connect attempt.
func TestRunTunnelInjectCredentialsWarnsWithoutExchangeURL(t *testing.T) {
	gwLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer gwLn.Close()
	accepted := make(chan struct{}, 1)
	go func() {
		for {
			c, err := gwLn.Accept()
			if err != nil {
				return
			}
			select {
			case accepted <- struct{}{}:
			default:
			}
			_ = c.Close()
		}
	}()

	ctx, cancel := context.WithCancel(context.Background())
	var buf bytes.Buffer
	cfg := config.Agent{
		AgentID:           "a1",
		GatewayAddr:       gwLn.Addr().String(),
		InjectCredentials: true,
	}
	errc := make(chan error, 1)
	go func() { errc <- RunTunnel(ctx, cfg, Deps{}, slog.New(slog.NewTextHandler(&buf, nil))) }()

	select {
	case <-accepted:
	case <-time.After(3 * time.Second):
		t.Fatal("gateway never saw a connection attempt")
	}
	cancel()
	select {
	case <-errc:
	case <-time.After(3 * time.Second):
		t.Fatal("RunTunnel did not stop after ctx cancellation")
	}
	if !strings.Contains(buf.String(), "SKYBRIDGE_CREDENTIAL_EXCHANGE_URL") {
		t.Fatalf("expected a credential-exchange-URL warning, got %q", buf.String())
	}
}

// TestRunTunnelInjectCredentialsEnabledWithResolver drives the "resolver configured" branch of
// RunTunnel's InjectCredentials handling, including the client-TLS-off sub-warning.
func TestRunTunnelInjectCredentialsEnabledWithResolver(t *testing.T) {
	gwLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer gwLn.Close()
	accepted := make(chan struct{}, 1)
	go func() {
		for {
			c, err := gwLn.Accept()
			if err != nil {
				return
			}
			select {
			case accepted <- struct{}{}:
			default:
			}
			_ = c.Close()
		}
	}()

	ctx, cancel := context.WithCancel(context.Background())
	var buf bytes.Buffer
	cfg := config.Agent{
		AgentID:               "a1",
		GatewayAddr:           gwLn.Addr().String(),
		InjectCredentials:     true,
		CredentialExchangeURL: "http://127.0.0.1:1",
	}
	errc := make(chan error, 1)
	go func() { errc <- RunTunnel(ctx, cfg, Deps{}, slog.New(slog.NewTextHandler(&buf, nil))) }()

	select {
	case <-accepted:
	case <-time.After(3 * time.Second):
		t.Fatal("gateway never saw a connection attempt")
	}
	cancel()
	select {
	case <-errc:
	case <-time.After(3 * time.Second):
		t.Fatal("RunTunnel did not stop after ctx cancellation")
	}
	out := buf.String()
	if !strings.Contains(out, "credential injection ENABLED") {
		t.Fatalf("expected an enabled message, got %q", out)
	}
	if !strings.Contains(out, "client TLS is OFF") {
		t.Fatalf("expected a client-TLS-off warning, got %q", out)
	}
}

// TestRunTunnelWireMtlsPresetCertLogsAndUses drives the hasPresetCert branch of RunTunnel's wire
// mTLS setup: a valid pre-issued client cert/key means the loop should build a *tls.Config and
// connect over mTLS rather than the bearer-token path.
func TestRunTunnelWireMtlsPresetCertLogsAndUses(t *testing.T) {
	certPEM, keyPEM, err := selfSignedCertPEMForTest(t)
	if err != nil {
		t.Fatal(err)
	}
	agentTLS := agentTestTLSConfig(t)

	gwLn, err := tls.Listen("tcp", "127.0.0.1:0", agentTLS)
	if err != nil {
		t.Fatal(err)
	}
	defer gwLn.Close()

	registered := make(chan struct{}, 1)
	go func() {
		for {
			conn, err := gwLn.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				sess := tunnel.Server(c)
				defer sess.Close()
				if _, err := sess.NextControl(); err != nil {
					return
				}
				_ = sess.SendControl(tunnel.Control{Kind: tunnel.KindRegisterAck, OK: true})
				select {
				case registered <- struct{}{}:
				default:
				}
			}(conn)
		}
	}()

	ctx, cancel := context.WithCancel(context.Background())
	var buf bytes.Buffer
	cfg := config.Agent{
		AgentID:               "a1",
		OrgID:                 "org-1",
		Token:                 "t",
		GatewayAddr:           gwLn.Addr().String(),
		WireMtlsClientCertPEM: certPEM,
		WireMtlsClientKeyPEM:  keyPEM,
	}
	errc := make(chan error, 1)
	go func() { errc <- RunTunnel(ctx, cfg, Deps{}, slog.New(slog.NewTextHandler(&buf, nil))) }()

	select {
	case <-registered:
	case <-time.After(3 * time.Second):
		t.Fatal("gateway never saw a completed registration")
	}
	cancel()
	select {
	case <-errc:
	case <-time.After(3 * time.Second):
		t.Fatal("RunTunnel did not stop after ctx cancellation")
	}
	out := buf.String()
	if !strings.Contains(out, "wire mTLS configured with a pre-issued client cert") {
		t.Fatalf("expected a preset-cert log line, got %q", out)
	}
	if !strings.Contains(out, `"mTLS"`) && !strings.Contains(out, "(mTLS,") {
		t.Fatalf("expected the connect log to note mTLS mode, got %q", out)
	}
}

// TestRunTunnelWireMtlsEnrollFailureRetries drives the non-preset, non-IAM wiremtls.EnsureMaterial
// path with an unreachable enroll URL, which must log a retry warning rather than return an error,
// then stop cleanly on ctx cancellation.
func TestRunTunnelWireMtlsEnrollFailureRetries(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	var buf bytes.Buffer
	cfg := config.Agent{
		AgentID:             "a1",
		GatewayAddr:         "127.0.0.1:1",
		WireMtlsEnrollURL:   "http://127.0.0.1:1",
		WireMtlsEnrollToken: "tok",
	}
	err := RunTunnel(ctx, cfg, Deps{}, slog.New(slog.NewTextHandler(&buf, nil)))
	if err != nil {
		t.Fatalf("expected RunTunnel to return nil on ctx timeout, got %v", err)
	}
	if !strings.Contains(buf.String(), "wire mTLS enroll") {
		t.Fatalf("expected a wire mTLS enroll retry log, got %q", buf.String())
	}
}
