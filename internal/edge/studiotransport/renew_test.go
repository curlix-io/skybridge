package studiotransport

// §10.8 (docs/design/skybridge-masking-architecture.md in curlix/curlix): proactive cert renewal
// before expiry, authenticated by the current still-valid cert rather than an enrollment token --
// mirrors internal/edge/transport/renew_test.go for the Studio Agent's transport.

import (
	"context"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"io"
	"log/slog"
	"math/big"
	"testing"
	"time"

	"github.com/curlix-io/skybridge/internal/certstore"
	studiov1 "github.com/curlix-io/skybridge/internal/genpb/curlix/studiogateway/v1"
)

// fakeRenewGateway serves only Renew, signing whatever CSR it's handed with the test CA -- mirrors
// fakeEnrollGateway in enroll_test.go but for the token-less renewal RPC.
type fakeRenewGateway struct {
	studiov1.UnimplementedStudioGatewayServer
	ca      *studioTestCA
	wantErr bool
}

func (g *fakeRenewGateway) Renew(ctx context.Context, req *studiov1.RenewRequest) (*studiov1.RenewResponse, error) {
	if g.wantErr {
		return nil, errors.New("renew rejected")
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
	notAfter := time.Now().Add(24 * time.Hour)
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(6),
		Subject:      pkix.Name{CommonName: "agent-1"},
		NotBefore:    time.Now().Add(-time.Minute),
		NotAfter:     notAfter,
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, g.ca.cert, csr.PublicKey, g.ca.key)
	if err != nil {
		return nil, err
	}
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	return &studiov1.RenewResponse{
		ClientCertPem: string(certPEM),
		CaBundlePem:   string(g.ca.pem),
		NotAfterUnix:  notAfter.Unix(),
	}, nil
}

// issuedStudioTestMaterial builds a client cert/key pair signed by ca, valid until notAfter -- for
// seeding a test's "current" material without going through Enroll/Renew.
func issuedStudioTestMaterial(t *testing.T, ca *studioTestCA, notAfter time.Time) (certPEM, keyPEM []byte) {
	t.Helper()
	keyPEM, csrPEM, err := generateKeyAndCSR("", "org-1", "agent-1")
	if err != nil {
		t.Fatalf("generateKeyAndCSR: %v", err)
	}
	block, _ := pem.Decode(csrPEM)
	if block == nil {
		t.Fatal("csr pem decode failed")
	}
	csr, err := x509.ParseCertificateRequest(block.Bytes)
	if err != nil {
		t.Fatalf("parse csr: %v", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(7),
		Subject:      pkix.Name{CommonName: "agent-1"},
		NotBefore:    time.Now().Add(-time.Minute),
		NotAfter:     notAfter,
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, ca.cert, csr.PublicKey, ca.key)
	if err != nil {
		t.Fatalf("sign cert: %v", err)
	}
	certPEM = pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	return certPEM, keyPEM
}

func TestClientRenewCertSucceeds(t *testing.T) {
	ca := newStudioTestCA(t)
	target, stop := startStudioTLSGRPCServer(t, ca, &fakeRenewGateway{ca: ca})
	defer stop()

	certPEM, keyPEM := issuedStudioTestMaterial(t, ca, time.Now().Add(time.Hour))
	current := &tlsMaterial{caBundlePEM: ca.pem, clientCertPEM: certPEM, clientKeyPEM: keyPEM}

	c := New(Config{
		Target:      target,
		TenantID:    "org-1",
		AgentID:     "agent-1",
		CABundlePEM: ca.pem,
		TLSDir:      t.TempDir(),
	}, slog.New(slog.NewTextHandler(io.Discard, nil)))

	renewed, err := c.renewCert(context.Background(), current)
	if err != nil {
		t.Fatalf("renewCert: %v", err)
	}
	if len(renewed.clientCertPEM) == 0 || len(renewed.clientKeyPEM) == 0 {
		t.Fatal("expected renewed client cert/key material")
	}
	if !certValid(renewed.clientCertPEM, certRenewSkew) {
		t.Fatal("renewed cert should be valid")
	}
	if string(renewed.clientKeyPEM) == string(current.clientKeyPEM) {
		t.Fatal("expected a fresh keypair on renewal, not the old key")
	}
}

func TestClientRenewCertPropagatesGatewayError(t *testing.T) {
	ca := newStudioTestCA(t)
	target, stop := startStudioTLSGRPCServer(t, ca, &fakeRenewGateway{ca: ca, wantErr: true})
	defer stop()

	certPEM, keyPEM := issuedStudioTestMaterial(t, ca, time.Now().Add(time.Hour))
	current := &tlsMaterial{caBundlePEM: ca.pem, clientCertPEM: certPEM, clientKeyPEM: keyPEM}

	c := New(Config{
		Target:      target,
		TenantID:    "org-1",
		AgentID:     "agent-1",
		CABundlePEM: ca.pem,
		TLSDir:      t.TempDir(),
	}, slog.New(slog.NewTextHandler(io.Discard, nil)))

	if _, err := c.renewCert(context.Background(), current); err == nil {
		t.Fatal("expected error to propagate from a rejected Renew call")
	}
}

func TestStudioRenewalLoopRenewsWhenWithinSkewAndPersists(t *testing.T) {
	ca := newStudioTestCA(t)
	target, stop := startStudioTLSGRPCServer(t, ca, &fakeRenewGateway{ca: ca})
	defer stop()

	dir := t.TempDir()
	c := New(Config{
		Target:      target,
		TenantID:    "org-1",
		AgentID:     "agent-1",
		CABundlePEM: ca.pem,
		TLSDir:      dir,
	}, slog.New(slog.NewTextHandler(io.Discard, nil)))

	initialCertPEM, initialKeyPEM := issuedStudioTestMaterial(t, ca, time.Now().Add(48*time.Hour))
	if err := certstore.NewDiskStore(dir).Save(context.Background(), &certstore.Material{
		CABundlePEM: ca.pem, ClientCertPEM: initialCertPEM, ClientKeyPEM: initialKeyPEM,
	}); err != nil {
		t.Fatalf("persist test material: %v", err)
	}

	origSkew, origInterval := proactiveRenewalSkew, proactiveRenewalCheckInterval
	proactiveRenewalSkew = 72 * time.Hour
	proactiveRenewalCheckInterval = 20 * time.Millisecond
	defer func() { proactiveRenewalSkew, proactiveRenewalCheckInterval = origSkew, origInterval }()

	ctx, cancel := context.WithCancel(context.Background())
	loopDone := make(chan struct{})
	go func() {
		c.renewalLoop(ctx)
		close(loopDone)
	}()
	defer func() {
		cancel()
		<-loopDone
	}()

	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		got, err := c.ensureTLSMaterial(context.Background())
		if err == nil && got != nil && string(got.clientCertPEM) != string(initialCertPEM) {
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatal("renewal loop did not renew the on-disk cert in time")
}
