package wiremtls

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"testing"
)

func TestGenerateSelfSignedServerCertProducesValidPair(t *testing.T) {
	certPEM, keyPEM, err := GenerateSelfSignedServerCert()
	if err != nil {
		t.Fatal(err)
	}
	if len(certPEM) == 0 || len(keyPEM) == 0 {
		t.Fatal("expected non-empty cert and key PEM")
	}

	block, _ := pem.Decode(certPEM)
	if block == nil || block.Type != "CERTIFICATE" {
		t.Fatalf("expected a CERTIFICATE PEM block, got %v", block)
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		t.Fatalf("parse certificate: %v", err)
	}
	if cert.Subject.CommonName != "skybridge-gateway" {
		t.Fatalf("unexpected CommonName: %q", cert.Subject.CommonName)
	}
	wantDNS := map[string]bool{"localhost": false, "skybridge-gateway": false}
	for _, name := range cert.DNSNames {
		if _, ok := wantDNS[name]; ok {
			wantDNS[name] = true
		}
	}
	for name, seen := range wantDNS {
		if !seen {
			t.Fatalf("expected DNSNames to include %q, got %v", name, cert.DNSNames)
		}
	}
}

func TestServerConfigBuildsRequireAndVerifyClientCert(t *testing.T) {
	certPEM, keyPEM, err := GenerateSelfSignedServerCert()
	if err != nil {
		t.Fatal(err)
	}
	// Reuse the self-signed cert as its own "CA bundle" purely to exercise a valid PEM parse path.
	cfg, err := ServerConfig(certPEM, keyPEM, certPEM)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.ClientAuth != tls.RequireAndVerifyClientCert {
		t.Fatalf("expected RequireAndVerifyClientCert, got %v", cfg.ClientAuth)
	}
	if len(cfg.Certificates) != 1 {
		t.Fatalf("expected exactly one certificate, got %d", len(cfg.Certificates))
	}
	if cfg.ClientCAs == nil {
		t.Fatal("expected ClientCAs pool to be set")
	}
}

func TestServerConfigRejectsMismatchedKeyPair(t *testing.T) {
	certPEM, _, err := GenerateSelfSignedServerCert()
	if err != nil {
		t.Fatal(err)
	}
	_, otherKeyPEM, err := GenerateSelfSignedServerCert()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := ServerConfig(certPEM, otherKeyPEM, certPEM); err == nil {
		t.Fatal("expected error for mismatched cert/key pair")
	}
}

func TestServerConfigRejectsInvalidCABundle(t *testing.T) {
	certPEM, keyPEM, err := GenerateSelfSignedServerCert()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := ServerConfig(certPEM, keyPEM, []byte("not a pem")); err == nil {
		t.Fatal("expected error for invalid CA bundle PEM")
	}
}
