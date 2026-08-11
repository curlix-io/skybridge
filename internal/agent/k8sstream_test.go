package agent

import (
	"bytes"
	"context"
	"log/slog"
	"net"
	"testing"
	"time"

	"github.com/curlix-io/skybridge/internal/config"
	"github.com/curlix-io/skybridge/internal/tunnel"
)

// openK8sStream opens a client stream against an in-memory server session and returns the server's
// accepted stream, ready to be handed to serveK8sStream.
func openK8sStream(t *testing.T) (*tunnel.Stream, func()) {
	t.Helper()
	clientEnd, serverEnd := net.Pipe()
	clientSess := tunnel.Client(clientEnd)
	serverSess := tunnel.Server(serverEnd)

	if _, err := clientSess.Open(tunnel.OpenMeta{Target: "cluster", Addr: "k8s.internal:6443", DBType: "kubernetes"}.Encode()); err != nil {
		t.Fatalf("open: %v", err)
	}
	st, err := serverSess.Accept()
	if err != nil {
		t.Fatalf("accept: %v", err)
	}
	return st, func() { clientSess.Close(); serverSess.Close() }
}

func TestServeK8sStreamMissingClientTLS(t *testing.T) {
	st, cleanup := openK8sStream(t)
	defer cleanup()

	var buf bytes.Buffer
	serveK8sStream(context.Background(), st, tunnel.OpenMeta{Target: "cluster", Addr: "x:6443"}, config.Agent{}, slog.New(slog.NewTextHandler(&buf, nil)))
	if !bytes.Contains(buf.Bytes(), []byte("SKYBRIDGE_K8S_CLIENT_TLS_CERT_PEM")) {
		t.Fatalf("expected a missing-client-TLS warning, got %q", buf.String())
	}
}

func TestServeK8sStreamMissingResolver(t *testing.T) {
	st, cleanup := openK8sStream(t)
	defer cleanup()

	certPEM, keyPEM, err := selfSignedCertPEMForTest(t)
	if err != nil {
		t.Fatal(err)
	}
	var buf bytes.Buffer
	cfg := config.Agent{K8sClientTLSCertPEM: certPEM, K8sClientTLSKeyPEM: keyPEM}
	serveK8sStream(context.Background(), st, tunnel.OpenMeta{Target: "cluster", Addr: "x:6443"}, cfg, slog.New(slog.NewTextHandler(&buf, nil)))
	if !bytes.Contains(buf.Bytes(), []byte("SKYBRIDGE_K8S_CREDENTIAL_EXCHANGE_URL")) {
		t.Fatalf("expected a missing-resolver warning, got %q", buf.String())
	}
}

func TestServeK8sStreamBadClientCertKey(t *testing.T) {
	st, cleanup := openK8sStream(t)
	defer cleanup()

	certPEM, _, err := selfSignedCertPEMForTest(t)
	if err != nil {
		t.Fatal(err)
	}
	_, keyPEM2, err := selfSignedCertPEMForTest(t)
	if err != nil {
		t.Fatal(err)
	}
	var buf bytes.Buffer
	cfg := config.Agent{
		K8sClientTLSCertPEM:      certPEM,
		K8sClientTLSKeyPEM:       keyPEM2, // mismatched key
		K8sCredentialExchangeURL: "http://127.0.0.1:0",
	}
	serveK8sStream(context.Background(), st, tunnel.OpenMeta{Target: "cluster", Addr: "x:6443"}, cfg, slog.New(slog.NewTextHandler(&buf, nil)))
	if !bytes.Contains(buf.Bytes(), []byte("client TLS cert/key")) {
		t.Fatalf("expected a cert/key error, got %q", buf.String())
	}
}

// TestServeK8sStreamProxyInjectFailsFastOnClosedClient drives serveK8sStream all the way to
// engine.ProxyInject (dial to a fake upstream succeeds), then lets the client-side stream close
// immediately so the TLS handshake ProxyInject attempts fails fast — exercising both the
// engine-construction/ProxyInject-call line and the error-logging branch right after it.
func TestServeK8sStreamProxyInjectFailsFastOnClosedClient(t *testing.T) {
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

	clientEnd, serverEnd := net.Pipe()
	clientSess := tunnel.Client(clientEnd)
	serverSess := tunnel.Server(serverEnd)
	if _, err := clientSess.Open(tunnel.OpenMeta{Target: "cluster", Addr: "k8s.internal:6443", DBType: "kubernetes"}.Encode()); err != nil {
		t.Fatalf("open: %v", err)
	}
	st, err := serverSess.Accept()
	if err != nil {
		t.Fatalf("accept: %v", err)
	}
	// Close the client side right away so the server stream's read returns EOF instead of
	// completing a TLS handshake.
	clientSess.Close()

	certPEM, keyPEM, err := selfSignedCertPEMForTest(t)
	if err != nil {
		t.Fatal(err)
	}
	var buf bytes.Buffer
	cfg := config.Agent{
		K8sClientTLSCertPEM:      certPEM,
		K8sClientTLSKeyPEM:       keyPEM,
		K8sCredentialExchangeURL: "http://127.0.0.1:0",
	}
	serveK8sStream(context.Background(), st, tunnel.OpenMeta{Target: "cluster", Addr: upstreamLn.Addr().String()}, cfg, slog.New(slog.NewTextHandler(&buf, nil)))
	serverSess.Close()
	if !bytes.Contains(buf.Bytes(), []byte("kubernetes proxy session ended")) {
		t.Fatalf("expected a proxy-session-ended log, got %q", buf.String())
	}
}

func TestServeK8sStreamDialFailure(t *testing.T) {
	st, cleanup := openK8sStream(t)
	defer cleanup()

	certPEM, keyPEM, err := selfSignedCertPEMForTest(t)
	if err != nil {
		t.Fatal(err)
	}
	var buf bytes.Buffer
	cfg := config.Agent{
		K8sClientTLSCertPEM:      certPEM,
		K8sClientTLSKeyPEM:       keyPEM,
		K8sCredentialExchangeURL: "http://127.0.0.1:0",
	}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	// Port 0 on an unreachable-ish loopback address dials fast-fail (connection refused).
	serveK8sStream(ctx, st, tunnel.OpenMeta{Target: "cluster", Addr: "127.0.0.1:1"}, cfg, slog.New(slog.NewTextHandler(&buf, nil)))
	if !bytes.Contains(buf.Bytes(), []byte("dial kubernetes API server")) {
		t.Fatalf("expected a dial-failure log, got %q", buf.String())
	}
}
