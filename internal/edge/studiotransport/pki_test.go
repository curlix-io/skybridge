//go:build querystudio

package studiotransport

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"testing"
	"time"
)

func TestGenerateKeyAndCSRCarriesSpiffeSAN(t *testing.T) {
	_, csrPEM, err := generateKeyAndCSR("", "org-1", "agent-a")
	if err != nil {
		t.Fatal(err)
	}
	block, _ := pem.Decode(csrPEM)
	if block == nil {
		t.Fatal("expected a decodable CSR PEM block")
	}
	csr, err := x509.ParseCertificateRequest(block.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	if len(csr.URIs) != 1 || csr.URIs[0].String() != "spiffe://skybridge.studio-agent/tenant/org-1/agent/agent-a" {
		t.Fatalf("unexpected CSR URIs: %v", csr.URIs)
	}
	if csr.Subject.CommonName != "agent-a" {
		t.Fatalf("expected CommonName agent-a, got %q", csr.Subject.CommonName)
	}
}

func TestGenerateKeyAndCSRDefaultsCommonNameWhenAgentEmpty(t *testing.T) {
	_, csrPEM, err := generateKeyAndCSR("", "org-1", "")
	if err != nil {
		t.Fatal(err)
	}
	block, _ := pem.Decode(csrPEM)
	csr, err := x509.ParseCertificateRequest(block.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	if csr.Subject.CommonName != "studio-agent" {
		t.Fatalf("expected default CommonName studio-agent, got %q", csr.Subject.CommonName)
	}
}

func TestServerTLSConfigNoCAUsesSystemRoots(t *testing.T) {
	cfg, err := serverTLSConfig(nil)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.RootCAs != nil {
		t.Fatal("expected nil RootCAs when caPEM is empty")
	}
}

func TestServerTLSConfigRejectsInvalidCA(t *testing.T) {
	if _, err := serverTLSConfig([]byte("not a pem")); err == nil {
		t.Fatal("expected an error for invalid CA PEM")
	}
}

// selfSignedMaterialForTest mints a self-signed ECDSA P-256 cert/key pair, reused both as the client
// material and (optionally) as its own CA bundle so mtlsTLSConfig's happy path is exercisable.
func selfSignedMaterialForTest(t *testing.T) (certPEM, keyPEM []byte) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber:          serial,
		Subject:               pkix.Name{CommonName: "test"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	keyDER, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	certPEM = pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	keyPEM = pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER})
	return certPEM, keyPEM
}

func TestMtlsTLSConfigRejectsInvalidCertKeyPair(t *testing.T) {
	m := &tlsMaterial{clientCertPEM: []byte("not a cert"), clientKeyPEM: []byte("not a key")}
	if _, err := mtlsTLSConfig(m); err == nil {
		t.Fatal("expected an error for an invalid cert/key pair")
	}
}

func TestMtlsTLSConfigBuildsFromValidPair(t *testing.T) {
	certPEM, keyPEM := selfSignedMaterialForTest(t)
	m := &tlsMaterial{clientCertPEM: certPEM, clientKeyPEM: keyPEM}
	cfg, err := mtlsTLSConfig(m)
	if err != nil {
		t.Fatal(err)
	}
	if len(cfg.Certificates) != 1 {
		t.Fatalf("expected one certificate, got %d", len(cfg.Certificates))
	}
	if cfg.RootCAs != nil {
		t.Fatal("expected nil RootCAs when no CA bundle is set")
	}
}

func TestMtlsTLSConfigWithCABundle(t *testing.T) {
	certPEM, keyPEM := selfSignedMaterialForTest(t)
	m := &tlsMaterial{clientCertPEM: certPEM, clientKeyPEM: keyPEM, caBundlePEM: certPEM}
	cfg, err := mtlsTLSConfig(m)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.RootCAs == nil {
		t.Fatal("expected RootCAs to be set when a CA bundle is provided")
	}
}

func TestMtlsTLSConfigRejectsInvalidCABundle(t *testing.T) {
	certPEM, keyPEM := selfSignedMaterialForTest(t)
	m := &tlsMaterial{clientCertPEM: certPEM, clientKeyPEM: keyPEM, caBundlePEM: []byte("not a pem")}
	if _, err := mtlsTLSConfig(m); err == nil {
		t.Fatal("expected an error for an invalid CA bundle")
	}
}
