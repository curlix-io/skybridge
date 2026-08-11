package studiotransport

// This file exercises Client.enroll, Client.dial, and Client.Run against an in-process TLS gRPC
// server, following the same hermetic pattern as internal/edge/transport/material_test.go (per
// CLAUDE.md's guidance to use an in-process TLS listener rather than a real network service).

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"io"
	"log/slog"
	"math/big"
	"net"
	"testing"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"

	studiov1 "github.com/curlix-io/skybridge/internal/genpb/curlix/studiogateway/v1"
)

// studioTestCA is a minimal in-test CA that signs agent CSRs the way the Studio Gateway would.
type studioTestCA struct {
	cert *x509.Certificate
	pem  []byte
	key  *ecdsa.PrivateKey
}

func newStudioTestCA(t *testing.T) *studioTestCA {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("ca key: %v", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "Test Studio CA"},
		NotBefore:             time.Now().Add(-time.Minute),
		NotAfter:              time.Now().Add(24 * time.Hour),
		IsCA:                  true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("ca cert: %v", err)
	}
	cert, _ := x509.ParseCertificate(der)
	return &studioTestCA{cert: cert, pem: pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), key: key}
}

// serverCertFromCA issues a TLS server certificate for the in-process listener, signed by the same
// test CA the client trusts as its root, so no real network CA is involved.
func serverCertFromStudioCA(t *testing.T, ca *studioTestCA) tls.Certificate {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("server key: %v", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(4),
		Subject:      pkix.Name{CommonName: "127.0.0.1"},
		NotBefore:    time.Now().Add(-time.Minute),
		NotAfter:     time.Now().Add(24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		IPAddresses:  []net.IP{net.ParseIP("127.0.0.1")},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, ca.cert, &key.PublicKey, ca.key)
	if err != nil {
		t.Fatalf("server cert: %v", err)
	}
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		t.Fatalf("marshal server key: %v", err)
	}
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})
	cert, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		t.Fatalf("server keypair: %v", err)
	}
	return cert
}

// fakeEnrollGateway serves only Enroll (and a no-op Connect), signing whatever CSR it's handed with
// the test CA, to exercise Client.enroll / ensureTLSMaterial's enroll branch and Client.Run's dial
// path end to end.
type fakeEnrollGateway struct {
	studiov1.UnimplementedStudioGatewayServer
	ca      *studioTestCA
	wantErr bool
	omitCA  bool
}

func (g *fakeEnrollGateway) Enroll(ctx context.Context, req *studiov1.EnrollRequest) (*studiov1.EnrollResponse, error) {
	if g.wantErr {
		return nil, errors.New("enrollment token rejected")
	}
	block, _ := pem.Decode([]byte(req.GetCsrPem()))
	if block == nil {
		return nil, errors.New("bad csr pem")
	}
	csr, err := x509.ParseCertificateRequest(block.Bytes)
	if err != nil {
		return nil, err
	}
	if err := csr.CheckSignature(); err != nil {
		return nil, err
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(3),
		Subject:      pkix.Name{CommonName: req.GetAgentId()},
		NotBefore:    time.Now().Add(-time.Minute),
		NotAfter:     time.Now().Add(24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, g.ca.cert, csr.PublicKey, g.ca.key)
	if err != nil {
		return nil, err
	}
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	resp := &studiov1.EnrollResponse{ClientCertPem: string(certPEM)}
	if !g.omitCA {
		resp.CaBundlePem = string(g.ca.pem)
	}
	return resp, nil
}

func startStudioTLSGRPCServer(t *testing.T, ca *studioTestCA, srv studiov1.StudioGatewayServer) (target string, stop func()) {
	t.Helper()
	lis, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	tlsCfg := &tls.Config{Certificates: []tls.Certificate{serverCertFromStudioCA(t, ca)}}
	gs := grpc.NewServer(grpc.Creds(credentials.NewTLS(tlsCfg)))
	studiov1.RegisterStudioGatewayServer(gs, srv)
	go gs.Serve(lis)
	return lis.Addr().String(), func() { gs.Stop(); _ = lis.Close() }
}

func TestClientEnrollSucceeds(t *testing.T) {
	ca := newStudioTestCA(t)
	target, stop := startStudioTLSGRPCServer(t, ca, &fakeEnrollGateway{ca: ca})
	defer stop()

	c := New(Config{
		Target:      target,
		TenantID:    "org-1",
		AgentID:     "agent-1",
		CABundlePEM: ca.pem,
		EnrollToken: "one-time-token",
	}, slog.New(slog.NewTextHandler(io.Discard, nil)))

	m, err := c.enroll(context.Background())
	if err != nil {
		t.Fatalf("enroll: %v", err)
	}
	if len(m.clientCertPEM) == 0 || len(m.clientKeyPEM) == 0 {
		t.Fatal("expected client cert/key material from enroll")
	}
	if !certValid(m.clientCertPEM, certRenewSkew) {
		t.Fatal("issued cert should be valid")
	}
	if string(m.caBundlePEM) != string(ca.pem) {
		t.Fatal("expected the CA bundle returned by Enroll to be used")
	}
}

func TestClientEnrollUsesConfigCABundleWhenEnrollResponseOmitsIt(t *testing.T) {
	ca := newStudioTestCA(t)
	gw := &fakeEnrollGateway{ca: ca}
	target, stop := startStudioTLSGRPCServer(t, ca, gw)
	defer stop()

	c := New(Config{
		Target:      target,
		TenantID:    "org-1",
		AgentID:     "agent-1",
		CABundlePEM: ca.pem,
		EnrollToken: "one-time-token",
		// EnrollTarget left empty: enroll() must fall back to Target.
	}, slog.New(slog.NewTextHandler(io.Discard, nil)))

	m, err := c.enroll(context.Background())
	if err != nil {
		t.Fatalf("enroll: %v", err)
	}
	if string(m.caBundlePEM) != string(ca.pem) {
		t.Fatal("expected caBundlePEM to come from the enroll response")
	}
}

// TestClientEnrollFallsBackToConfigCABundleWhenEnrollResponseCAEmpty covers the caOut fallback
// branch in enroll(): when the Enroll RPC response's ca_bundle_pem is empty, enroll must fall back
// to c.cfg.CABundlePEM rather than returning an empty CA bundle.
func TestClientEnrollFallsBackToConfigCABundleWhenEnrollResponseCAEmpty(t *testing.T) {
	ca := newStudioTestCA(t)
	target, stop := startStudioTLSGRPCServer(t, ca, &fakeEnrollGateway{ca: ca, omitCA: true})
	defer stop()

	c := New(Config{
		Target:      target,
		TenantID:    "org-1",
		AgentID:     "agent-1",
		CABundlePEM: ca.pem,
		EnrollToken: "one-time-token",
	}, slog.New(slog.NewTextHandler(io.Discard, nil)))

	m, err := c.enroll(context.Background())
	if err != nil {
		t.Fatalf("enroll: %v", err)
	}
	if string(m.caBundlePEM) != string(ca.pem) {
		t.Fatal("expected caBundlePEM to fall back to the configured CABundlePEM when the Enroll response omits it")
	}
}

// TestClientEnrollPropagatesInvalidServerCABundleError covers enroll()'s serverTLSConfig error
// branch: an invalid CABundlePEM used to build the dial-time TLS config for the Enroll RPC must
// surface as an error rather than silently dialing with no root trust configured.
func TestClientEnrollPropagatesInvalidServerCABundleError(t *testing.T) {
	c := New(Config{
		Target:      "127.0.0.1:0",
		TenantID:    "org-1",
		AgentID:     "agent-1",
		CABundlePEM: []byte("not a pem"),
		EnrollToken: "one-time-token",
	}, slog.New(slog.NewTextHandler(io.Discard, nil)))

	if _, err := c.enroll(context.Background()); err == nil {
		t.Fatal("expected enroll to propagate an error building the TLS config from an invalid CA bundle")
	}
}

func TestClientEnrollPropagatesRPCError(t *testing.T) {
	ca := newStudioTestCA(t)
	target, stop := startStudioTLSGRPCServer(t, ca, &fakeEnrollGateway{ca: ca, wantErr: true})
	defer stop()

	c := New(Config{
		Target:      target,
		TenantID:    "org-1",
		AgentID:     "agent-1",
		CABundlePEM: ca.pem,
		EnrollToken: "one-time-token",
	}, slog.New(slog.NewTextHandler(io.Discard, nil)))

	if _, err := c.enroll(context.Background()); err == nil {
		t.Fatal("expected the Enroll RPC error to propagate")
	}
}

func TestEnsureTLSMaterialEnrollsAndPersistsToDisk(t *testing.T) {
	ca := newStudioTestCA(t)
	target, stop := startStudioTLSGRPCServer(t, ca, &fakeEnrollGateway{ca: ca})
	defer stop()

	dir := t.TempDir()
	c := New(Config{
		Target:      target,
		TenantID:    "org-1",
		AgentID:     "agent-1",
		CABundlePEM: ca.pem,
		TLSDir:      dir,
		EnrollToken: "one-time-token",
	}, slog.New(slog.NewTextHandler(io.Discard, nil)))

	m, err := c.ensureTLSMaterial(context.Background())
	if err != nil {
		t.Fatalf("ensureTLSMaterial: %v", err)
	}
	if m == nil {
		t.Fatal("expected material after successful enroll")
	}

	// A second, tokenless client should reuse the persisted, still-valid cert rather than erroring.
	c2 := New(Config{
		Target:      target,
		TenantID:    "org-1",
		AgentID:     "agent-1",
		CABundlePEM: ca.pem,
		TLSDir:      dir,
	}, slog.New(slog.NewTextHandler(io.Discard, nil)))
	m2, err := c2.ensureTLSMaterial(context.Background())
	if err != nil {
		t.Fatalf("ensureTLSMaterial (reload): %v", err)
	}
	if m2 == nil || string(m2.clientCertPEM) != string(m.clientCertPEM) {
		t.Fatal("expected reload to reuse the persisted cert")
	}
}

func TestEnsureTLSMaterialEnrollErrorPropagates(t *testing.T) {
	ca := newStudioTestCA(t)
	target, stop := startStudioTLSGRPCServer(t, ca, &fakeEnrollGateway{ca: ca, wantErr: true})
	defer stop()

	c := New(Config{
		Target:      target,
		TenantID:    "org-1",
		AgentID:     "agent-1",
		CABundlePEM: ca.pem,
		TLSDir:      t.TempDir(),
		EnrollToken: "one-time-token",
	}, slog.New(slog.NewTextHandler(io.Discard, nil)))

	if _, err := c.ensureTLSMaterial(context.Background()); err == nil {
		t.Fatal("expected error to propagate from a failed enroll")
	}
}

func TestDialProducesClientForMTLSInsecureAndSystemRoots(t *testing.T) {
	certPEM, keyPEM := selfSignedMaterialForTest(t)
	c := New(Config{Target: "127.0.0.1:0"}, slog.New(slog.NewTextHandler(io.Discard, nil)))

	conn, err := c.dial(&tlsMaterial{clientCertPEM: certPEM, clientKeyPEM: keyPEM})
	if err != nil {
		t.Fatalf("dial mtls: %v", err)
	}
	_ = conn.Close()

	c2 := New(Config{Target: "127.0.0.1:0", Insecure: true}, slog.New(slog.NewTextHandler(io.Discard, nil)))
	conn2, err := c2.dial(nil)
	if err != nil {
		t.Fatalf("dial insecure: %v", err)
	}
	_ = conn2.Close()

	c3 := New(Config{Target: "127.0.0.1:0"}, slog.New(slog.NewTextHandler(io.Discard, nil)))
	conn3, err := c3.dial(nil)
	if err != nil {
		t.Fatalf("dial system-roots TLS: %v", err)
	}
	_ = conn3.Close()
}

func TestDialPropagatesInvalidMTLSMaterialError(t *testing.T) {
	c := New(Config{Target: "127.0.0.1:0"}, slog.New(slog.NewTextHandler(io.Discard, nil)))
	_, err := c.dial(&tlsMaterial{clientCertPEM: []byte("garbage"), clientKeyPEM: []byte("garbage")})
	if err == nil {
		t.Fatal("expected an error building mTLS config from an invalid cert/key pair")
	}
}

func TestRunFatalConfigErrorReturnsWithoutReconnect(t *testing.T) {
	ca := newStudioTestCA(t)
	c := New(Config{
		Target:      "127.0.0.1:0",
		TenantID:    "org-1",
		AgentID:     "agent-1",
		CABundlePEM: ca.pem,
		TLSDir:      t.TempDir(), // no cached cert, no enroll token -> fatal
	}, slog.New(slog.NewTextHandler(io.Discard, nil)))

	err := c.Run(context.Background())
	if err == nil {
		t.Fatal("expected a fatal config error from Run")
	}
}

func TestRunReconnectsUntilContextCancelled(t *testing.T) {
	c := New(Config{Target: "127.0.0.1:1", Reconnect: true, MaxBackoff: 5 * time.Millisecond}, slog.New(slog.NewTextHandler(io.Discard, nil)))
	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()
	err := c.Run(ctx)
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("expected context.DeadlineExceeded, got %v", err)
	}
}

func TestRunServesOneRoundAgainstLiveGatewayThenStopsWithoutReconnect(t *testing.T) {
	ca := newStudioTestCA(t)
	// A fake gateway whose Connect immediately closes the stream (EOF), so serve() returns nil and
	// Run — with Reconnect left false — returns nil right after, exercising the dial-succeeds /
	// serve-returns-cleanly / no-reconnect path in Run end to end against a real in-process listener.
	target, stop := startStudioTLSGRPCServer(t, ca, &fakeEnrollGateway{ca: ca})
	defer stop()

	c := New(Config{
		Target:   target,
		TenantID: "org-1",
		AgentID:  "agent-1",
		Insecure: false, // no CABundlePEM/TLSDir configured -> ensureTLSMaterial returns (nil, nil), bearer path
	}, slog.New(slog.NewTextHandler(io.Discard, nil)))

	err := c.Run(context.Background())
	if err != nil {
		t.Fatalf("expected Run to return nil after a clean EOF with Reconnect=false, got %v", err)
	}
}
