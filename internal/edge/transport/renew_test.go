package transport

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
	"net/url"
	"testing"
	"time"

	"github.com/curlix-io/skybridge/internal/certstore"
	connectorv1 "github.com/curlix-io/skybridge/internal/genpb/curlix/connector/v1"
)

// §10.8 (docs/design/skybridge-masking-architecture.md in curlix/curlix): proactive cert renewal
// before expiry, authenticated by the current still-valid cert rather than an enrollment token.

// fakeRenewGateway serves only Renew, signing whatever CSR it's handed with the test CA -- mirrors
// fakeEnrollGateway in material_test.go but for the token-less renewal RPC. Signs inline (rather
// than via testCA.sign, which needs a *testing.T for t.Fatal) since this runs inside a gRPC
// handler goroutine, not the test goroutine.
type fakeRenewGateway struct {
	connectorv1.UnimplementedConnectorGatewayServer
	ca      *testCA
	wantErr bool
}

func (g *fakeRenewGateway) Renew(ctx context.Context, req *connectorv1.RenewRequest) (*connectorv1.RenewResponse, error) {
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
	uri, _ := url.Parse(spiffeID("skybridge.connector", "org-1", "edge-1"))
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(5),
		Subject:      pkix.Name{CommonName: "edge-1"},
		NotBefore:    time.Now().Add(-time.Minute),
		NotAfter:     notAfter,
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
		URIs:         []*url.URL{uri},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, g.ca.cert, csr.PublicKey, g.ca.key)
	if err != nil {
		return nil, err
	}
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	return &connectorv1.RenewResponse{
		ClientCertPem: string(certPEM),
		CaBundlePem:   string(g.ca.certPEM),
		NotAfterUnix:  notAfter.Unix(),
	}, nil
}

// issuedTestMaterial builds a client cert/key pair signed by ca, valid until notAfter -- for
// seeding a test's "current" material without going through Enroll/Renew.
func issuedTestMaterial(t *testing.T, ca *testCA, notAfter time.Time) (certPEM, keyPEM []byte) {
	t.Helper()
	keyPEM, csrPEM, err := generateKeyAndCSR(DefaultTrustDomain, "org-1", "edge-1")
	if err != nil {
		t.Fatalf("generateKeyAndCSR: %v", err)
	}
	certPEM = ca.sign(t, csrPEM, "org-1", "edge-1", notAfter)
	return certPEM, keyPEM
}

func TestClientRenewCertSucceeds(t *testing.T) {
	ca := newTestCA(t)
	target, stop := startTLSGRPCServer(t, ca, &fakeRenewGateway{ca: ca})
	defer stop()

	certPEM, keyPEM := issuedTestMaterial(t, ca, time.Now().Add(time.Hour))
	current := &tlsMaterial{caBundlePEM: ca.certPEM, clientCertPEM: certPEM, clientKeyPEM: keyPEM}

	c := New(Config{
		Target:      target,
		TenantID:    "org-1",
		ConnectorID: "edge-1",
		CABundlePEM: ca.certPEM,
		TLSDir:      t.TempDir(),
	}, nil, slog.New(slog.NewTextHandler(io.Discard, nil)))

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
	// A fresh keypair is generated for the renewal, not a reuse of the old key.
	if string(renewed.clientKeyPEM) == string(current.clientKeyPEM) {
		t.Fatal("expected a fresh keypair on renewal, not the old key")
	}
}

func TestClientRenewCertPropagatesGatewayError(t *testing.T) {
	ca := newTestCA(t)
	target, stop := startTLSGRPCServer(t, ca, &fakeRenewGateway{ca: ca, wantErr: true})
	defer stop()

	certPEM, keyPEM := issuedTestMaterial(t, ca, time.Now().Add(time.Hour))
	current := &tlsMaterial{caBundlePEM: ca.certPEM, clientCertPEM: certPEM, clientKeyPEM: keyPEM}

	c := New(Config{
		Target:      target,
		TenantID:    "org-1",
		ConnectorID: "edge-1",
		CABundlePEM: ca.certPEM,
	}, nil, slog.New(slog.NewTextHandler(io.Discard, nil)))

	if _, err := c.renewCert(context.Background(), current); err == nil {
		t.Fatal("expected error to propagate from a rejected Renew call")
	}
}

func TestRenewalLoopRenewsWhenWithinSkewAndPersists(t *testing.T) {
	ca := newTestCA(t)
	target, stop := startTLSGRPCServer(t, ca, &fakeRenewGateway{ca: ca})
	defer stop()

	dir := t.TempDir()
	c := New(Config{
		Target:      target,
		TenantID:    "org-1",
		ConnectorID: "edge-1",
		CABundlePEM: ca.certPEM,
		TLSDir:      dir,
	}, nil, slog.New(slog.NewTextHandler(io.Discard, nil)))

	// Persist an already-issued (but not-yet-expired) cert so ensureTLSMaterial finds it without
	// needing to enroll -- the renewal loop's own job starts from there.
	initialCertPEM, initialKeyPEM := issuedTestMaterial(t, ca, time.Now().Add(48*time.Hour))
	if err := certstore.NewDiskStore(dir).Save(context.Background(), &certstore.Material{
		CABundlePEM: ca.certPEM, ClientCertPEM: initialCertPEM, ClientKeyPEM: initialKeyPEM,
	}); err != nil {
		t.Fatalf("persist test material: %v", err)
	}

	// A cert expiring in 48h is always "within the renewal window" against a skew this wide, so
	// the loop renews on its very first tick instead of waiting out a real expiry.
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
		<-loopDone // wait for the goroutine to actually stop before the deferred var restore runs
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
