package transport

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
	"log"
	"math/big"
	"net"
	"testing"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"

	connectorv1 "github.com/curlix-io/skybridge/internal/genpb/curlix/connector/v1"
)

// fakeEnrollGateway serves only Enroll, signing the CSR it's handed with the test CA — this
// exercises Client.enroll (and ensureTLSMaterial's enroll branch) over a real in-process TLS
// listener, per CLAUDE.md's guidance to use an in-process TLS server rather than a real network
// service.
type fakeEnrollGateway struct {
	connectorv1.UnimplementedConnectorGatewayServer
	ca      *testCA
	wantErr bool
}

func (g *fakeEnrollGateway) Enroll(ctx context.Context, req *connectorv1.EnrollRequest) (*connectorv1.EnrollResponse, error) {
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
		Subject:      pkix.Name{CommonName: req.GetConnectorId()},
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
	return &connectorv1.EnrollResponse{
		ClientCertPem: string(certPEM),
		CaBundlePem:   string(g.ca.certPEM),
	}, nil
}

// serverCertFromCA issues a TLS server certificate (for the in-process listener itself) signed by
// the same test CA, so a client trusting ca.certPEM as its root also trusts this listener —
// avoiding any reliance on a real network CA.
func serverCertFromCA(t *testing.T, ca *testCA) tls.Certificate {
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

func startTLSGRPCServer(t *testing.T, ca *testCA, srv connectorv1.ConnectorGatewayServer) (target string, stop func()) {
	t.Helper()
	lis, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	tlsCfg := &tls.Config{Certificates: []tls.Certificate{serverCertFromCA(t, ca)}}
	gs := grpc.NewServer(grpc.Creds(credentials.NewTLS(tlsCfg)))
	connectorv1.RegisterConnectorGatewayServer(gs, srv)
	go gs.Serve(lis)
	return lis.Addr().String(), func() { gs.Stop(); _ = lis.Close() }
}

func TestClientEnrollSucceeds(t *testing.T) {
	ca := newTestCA(t)
	target, stop := startTLSGRPCServer(t, ca, &fakeEnrollGateway{ca: ca})
	defer stop()

	c := New(Config{
		Target:      target,
		TenantID:    "org-1",
		ConnectorID: "edge-1",
		CABundlePEM: ca.certPEM,
		EnrollToken: "one-time-token",
	}, nil, log.New(io.Discard, "", 0))

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
}

func TestEnsureTLSMaterialEnrollErrorPropagates(t *testing.T) {
	ca := newTestCA(t)
	target, stop := startTLSGRPCServer(t, ca, &fakeEnrollGateway{ca: ca, wantErr: true})
	defer stop()

	c := New(Config{
		Target:      target,
		TenantID:    "org-1",
		ConnectorID: "edge-1",
		CABundlePEM: ca.certPEM,
		TLSDir:      t.TempDir(),
		EnrollToken: "one-time-token",
	}, nil, log.New(io.Discard, "", 0))

	if _, err := c.ensureTLSMaterial(context.Background()); err == nil {
		t.Fatal("expected error to propagate from failed enroll")
	}
}

func TestEnsureTLSMaterialEnrollsAndPersistsToDisk(t *testing.T) {
	ca := newTestCA(t)
	target, stop := startTLSGRPCServer(t, ca, &fakeEnrollGateway{ca: ca})
	defer stop()

	dir := t.TempDir()
	c := New(Config{
		Target:      target,
		TenantID:    "org-1",
		ConnectorID: "edge-1",
		CABundlePEM: ca.certPEM,
		TLSDir:      dir,
		EnrollToken: "one-time-token",
	}, nil, log.New(io.Discard, "", 0))

	m, err := c.ensureTLSMaterial(context.Background())
	if err != nil {
		t.Fatalf("ensureTLSMaterial: %v", err)
	}
	if m == nil {
		t.Fatal("expected material after successful enroll")
	}

	// A second call should find the freshly persisted, still-valid cert on disk and skip enroll
	// entirely (no EnrollToken needed this time).
	c2 := New(Config{
		Target:      target,
		TenantID:    "org-1",
		ConnectorID: "edge-1",
		CABundlePEM: ca.certPEM,
		TLSDir:      dir,
	}, nil, log.New(io.Discard, "", 0))
	m2, err := c2.ensureTLSMaterial(context.Background())
	if err != nil {
		t.Fatalf("ensureTLSMaterial (reload): %v", err)
	}
	if m2 == nil || string(m2.clientCertPEM) != string(m.clientCertPEM) {
		t.Fatal("expected reload to reuse the persisted cert")
	}
}

func TestEnsureTLSMaterialExpiredNoTokenReusesStale(t *testing.T) {
	ca := newTestCA(t)
	keyPEM, csrPEM, err := generateKeyAndCSR("", "org-1", "edge-1")
	if err != nil {
		t.Fatalf("generate: %v", err)
	}
	certPEM := ca.sign(t, csrPEM, "org-1", "edge-1", time.Now().Add(10*time.Minute)) // within renew skew

	dir := t.TempDir()
	mustWrite(t, dir+"/ca.pem", ca.certPEM)
	mustWrite(t, dir+"/client.crt", certPEM)
	mustWrite(t, dir+"/client.key", keyPEM)

	c := New(Config{
		TenantID:    "org-1",
		ConnectorID: "edge-1",
		CABundlePEM: ca.certPEM,
		TLSDir:      dir,
		// No EnrollToken: expired-but-no-token path must reuse the stale material rather than error.
	}, nil, log.New(io.Discard, "", 0))

	m, err := c.ensureTLSMaterial(context.Background())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if m == nil || string(m.clientCertPEM) != string(certPEM) {
		t.Fatal("expected stale material to be reused when no enroll token is available")
	}
}

func TestServerTLSConfigRejectsInvalidCABundle(t *testing.T) {
	if _, err := serverTLSConfig([]byte("not a pem")); err == nil {
		t.Fatal("expected error for invalid CA bundle PEM")
	}
}

func TestServerTLSConfigNoCAUsesSystemRoots(t *testing.T) {
	cfg, err := serverTLSConfig(nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if cfg.RootCAs != nil {
		t.Fatal("expected nil RootCAs (system roots) when no CA bundle given")
	}
}

func TestMtlsTLSConfigRejectsInvalidKeypair(t *testing.T) {
	m := &tlsMaterial{
		caBundlePEM:   []byte("garbage"),
		clientCertPEM: []byte("garbage-cert"),
		clientKeyPEM:  []byte("garbage-key"),
	}
	if _, err := mtlsTLSConfig(m); err == nil {
		t.Fatal("expected error for invalid client keypair")
	}
}

func TestMtlsTLSConfigRejectsInvalidCABundle(t *testing.T) {
	ca := newTestCA(t)
	keyPEM, csrPEM, _ := generateKeyAndCSR("", "org-1", "edge-1")
	certPEM := ca.sign(t, csrPEM, "org-1", "edge-1", time.Now().Add(24*time.Hour))
	m := &tlsMaterial{caBundlePEM: []byte("not a valid ca bundle"), clientCertPEM: certPEM, clientKeyPEM: keyPEM}
	if _, err := mtlsTLSConfig(m); err == nil {
		t.Fatal("expected error for invalid CA bundle")
	}
}

func TestTLSDirDefault(t *testing.T) {
	c := New(Config{}, nil, log.New(io.Discard, "", 0))
	if got := c.tlsDir(); got != "/var/lib/skybridge/tls" {
		t.Fatalf("unexpected default tls dir: %q", got)
	}
}

func TestCertValidRejectsUnparseableCert(t *testing.T) {
	if certValid([]byte("not a pem"), certRenewSkew) {
		t.Fatal("expected invalid for unparseable cert")
	}
}
