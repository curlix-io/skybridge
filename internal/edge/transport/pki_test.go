package transport

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"io"
	"log"
	"math/big"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// testCA is a minimal in-test CA that signs connector CSRs the way the gateway would.
type testCA struct {
	cert    *x509.Certificate
	certPEM []byte
	key     *ecdsa.PrivateKey
}

func newTestCA(t *testing.T) *testCA {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("ca key: %v", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "Test Edge CA"},
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
	return &testCA{cert: cert, certPEM: pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), key: key}
}

// sign validates the CSR and issues a client cert with the authoritative SPIFFE SAN (server-set).
func (ca *testCA) sign(t *testing.T, csrPEM []byte, tenant, connector string, notAfter time.Time) []byte {
	t.Helper()
	block, _ := pem.Decode(csrPEM)
	if block == nil {
		t.Fatal("csr pem decode failed")
	}
	csr, err := x509.ParseCertificateRequest(block.Bytes)
	if err != nil {
		t.Fatalf("parse csr: %v", err)
	}
	if err := csr.CheckSignature(); err != nil {
		t.Fatalf("csr signature invalid: %v", err)
	}
	uri, _ := url.Parse(spiffeID("curlix.connector", tenant, connector)) // gateway's own trust domain
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(2),
		Subject:      pkix.Name{CommonName: connector},
		NotBefore:    time.Now().Add(-time.Minute),
		NotAfter:     notAfter,
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
		URIs:         []*url.URL{uri},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, ca.cert, csr.PublicKey, ca.key)
	if err != nil {
		t.Fatalf("sign cert: %v", err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
}

func TestGenerateKeyAndCSRHasSpiffeSAN(t *testing.T) {
	keyPEM, csrPEM, err := generateKeyAndCSR("example.test", "org-1", "edge-7")
	if err != nil {
		t.Fatalf("generate: %v", err)
	}
	if b, _ := pem.Decode(keyPEM); b == nil || b.Type != "PRIVATE KEY" {
		t.Fatalf("bad key pem")
	}
	block, _ := pem.Decode(csrPEM)
	if block == nil {
		t.Fatal("csr pem decode failed")
	}
	csr, err := x509.ParseCertificateRequest(block.Bytes)
	if err != nil {
		t.Fatalf("parse csr: %v", err)
	}
	if err := csr.CheckSignature(); err != nil {
		t.Fatalf("csr signature: %v", err)
	}
	if csr.Subject.CommonName != "edge-7" {
		t.Fatalf("cn = %q", csr.Subject.CommonName)
	}
	if len(csr.URIs) != 1 || csr.URIs[0].String() != "spiffe://example.test/tenant/org-1/connector/edge-7" {
		t.Fatalf("unexpected SANs: %v", csr.URIs)
	}
}

func TestSignedMaterialBuildsTLSConfig(t *testing.T) {
	ca := newTestCA(t)
	keyPEM, csrPEM, err := generateKeyAndCSR("", "org-1", "edge-1")
	if err != nil {
		t.Fatalf("generate: %v", err)
	}
	certPEM := ca.sign(t, csrPEM, "org-1", "edge-1", time.Now().Add(24*time.Hour))
	m := &tlsMaterial{caBundlePEM: ca.certPEM, clientCertPEM: certPEM, clientKeyPEM: keyPEM}
	if !certValid(certPEM, certRenewSkew) {
		t.Fatal("freshly signed cert should be valid")
	}
	if _, err := mtlsTLSConfig(m); err != nil {
		t.Fatalf("mtlsTLSConfig: %v", err)
	}
}

func TestCertValidRejectsExpiring(t *testing.T) {
	ca := newTestCA(t)
	_, csrPEM, _ := generateKeyAndCSR("", "org-1", "edge-1")
	// Expires in 10 minutes; with a 1h skew it must be treated as invalid.
	certPEM := ca.sign(t, csrPEM, "org-1", "edge-1", time.Now().Add(10*time.Minute))
	if certValid(certPEM, certRenewSkew) {
		t.Fatal("near-expiry cert should be invalid under renew skew")
	}
}

func newTestClient(cfg Config) *Client {
	return New(cfg, nil, log.New(io.Discard, "", 0))
}

func TestEnsureTLSMaterialBearerWhenNoCA(t *testing.T) {
	c := newTestClient(Config{TenantID: "org-1", ConnectorID: "edge-1"})
	m, err := c.ensureTLSMaterial(context.Background())
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	if m != nil {
		t.Fatal("expected bearer (nil material) when no CA configured")
	}
}

func TestEnsureTLSMaterialFromDisk(t *testing.T) {
	ca := newTestCA(t)
	keyPEM, csrPEM, _ := generateKeyAndCSR("", "org-1", "edge-1")
	certPEM := ca.sign(t, csrPEM, "org-1", "edge-1", time.Now().Add(24*time.Hour))

	dir := t.TempDir()
	mustWrite(t, filepath.Join(dir, "ca.pem"), ca.certPEM)
	mustWrite(t, filepath.Join(dir, "client.crt"), certPEM)
	mustWrite(t, filepath.Join(dir, "client.key"), keyPEM)

	c := newTestClient(Config{
		TenantID:    "org-1",
		ConnectorID: "edge-1",
		CABundlePEM: ca.certPEM,
		TLSDir:      dir,
	})
	m, err := c.ensureTLSMaterial(context.Background())
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	if m == nil {
		t.Fatal("expected material loaded from disk")
	}
	if !strings.Contains(string(m.clientCertPEM), "CERTIFICATE") {
		t.Fatal("client cert not loaded")
	}
}

func TestEnsureTLSMaterialNoCertNoTokenErrors(t *testing.T) {
	ca := newTestCA(t)
	c := newTestClient(Config{
		TenantID:    "org-1",
		ConnectorID: "edge-1",
		CABundlePEM: ca.certPEM,
		TLSDir:      t.TempDir(), // empty dir: no cert on disk
	})
	if _, err := c.ensureTLSMaterial(context.Background()); err == nil {
		t.Fatal("expected error when CA present but no cert and no enroll token")
	}
}

func mustWrite(t *testing.T, path string, data []byte) {
	t.Helper()
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatalf("write %s: %v", path, err)
	}
}
