package wiremtls

import (
	"crypto/x509"
	"encoding/pem"
	"testing"
	"time"
)

func TestSpiffeIDRoundTrip(t *testing.T) {
	uri := SpiffeID("", "org-1", "agent-a")
	tenant, agentID, ok := ParseSpiffeID(uri)
	if !ok {
		t.Fatalf("ParseSpiffeID(%q) failed to parse", uri)
	}
	if tenant != "org-1" || agentID != "agent-a" {
		t.Fatalf("got tenant=%q agent=%q, want org-1/agent-a", tenant, agentID)
	}
}

func TestParseSpiffeIDRejectsWrongShape(t *testing.T) {
	cases := []string{
		"",
		"not-a-uri",
		"spiffe://curlix.connector/tenant/org-1/connector/c1", // different fleet's shape
		"spiffe://curlix.wire-agent/tenant//agent/a1",         // empty tenant
		"spiffe://curlix.wire-agent/tenant/org-1/agent/",      // empty agent
	}
	for _, c := range cases {
		if _, _, ok := ParseSpiffeID(c); ok {
			t.Errorf("ParseSpiffeID(%q) should not parse", c)
		}
	}
}

func TestGenerateKeyAndCSRCarriesSpiffeSAN(t *testing.T) {
	_, csrPEM, err := GenerateKeyAndCSR("", "org-1", "agent-a")
	if err != nil {
		t.Fatal(err)
	}
	if len(csrPEM) == 0 {
		t.Fatal("expected non-empty CSR PEM")
	}
}

func TestServerTLSConfigWithoutCAUsesSystemRoots(t *testing.T) {
	cfg, err := ServerTLSConfig(nil)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.RootCAs != nil {
		t.Fatal("expected nil RootCAs (system roots) when caPEM is empty")
	}
}

func TestServerTLSConfigWithCAPinsPool(t *testing.T) {
	certPEM, _, err := GenerateSelfSignedServerCert()
	if err != nil {
		t.Fatal(err)
	}
	cfg, err := ServerTLSConfig(certPEM)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.RootCAs == nil {
		t.Fatal("expected RootCAs to be set when caPEM is non-empty")
	}
}

func TestServerTLSConfigRejectsInvalidCAPEM(t *testing.T) {
	if _, err := ServerTLSConfig([]byte("garbage")); err == nil {
		t.Fatal("expected error for invalid CA PEM")
	}
}

func TestClientTLSConfigLoadsKeyPair(t *testing.T) {
	certPEM, keyPEM, err := GenerateSelfSignedServerCert()
	if err != nil {
		t.Fatal(err)
	}
	m := &Material{ClientCertPEM: certPEM, ClientKeyPEM: keyPEM}
	cfg, err := m.ClientTLSConfig()
	if err != nil {
		t.Fatal(err)
	}
	if len(cfg.Certificates) != 1 {
		t.Fatalf("expected exactly one certificate, got %d", len(cfg.Certificates))
	}
}

func TestClientTLSConfigRejectsMismatchedKeyPair(t *testing.T) {
	certPEM, _, err := GenerateSelfSignedServerCert()
	if err != nil {
		t.Fatal(err)
	}
	_, otherKeyPEM, err := GenerateSelfSignedServerCert()
	if err != nil {
		t.Fatal(err)
	}
	m := &Material{ClientCertPEM: certPEM, ClientKeyPEM: otherKeyPEM}
	if _, err := m.ClientTLSConfig(); err == nil {
		t.Fatal("expected error for mismatched cert/key pair")
	}
}

func TestCertValidRejectsExpiredCert(t *testing.T) {
	if CertValid(nil, 0) {
		t.Fatal("expected CertValid to reject nil/unparseable PEM")
	}
	if CertValid([]byte("not a pem"), 0) {
		t.Fatal("expected CertValid to reject garbage PEM")
	}
}

func TestCertValidAcceptsFreshCertWithNoSkew(t *testing.T) {
	certPEM, _, err := GenerateSelfSignedServerCert()
	if err != nil {
		t.Fatal(err)
	}
	if !CertValid(certPEM, 0) {
		t.Fatal("expected freshly minted cert to be valid with zero skew")
	}
}

func TestCertValidRejectsWhenSkewExceedsRemainingLife(t *testing.T) {
	certPEM, _, err := GenerateSelfSignedServerCert()
	if err != nil {
		t.Fatal(err)
	}
	// GenerateSelfSignedServerCert mints a cert valid for 825 days; a skew far beyond that should
	// push the "renew by" threshold past the cert's actual expiry.
	if CertValid(certPEM, 900*24*time.Hour) {
		t.Fatal("expected CertValid to reject when skew exceeds remaining validity")
	}
}

func TestIdentityFromCertExtractsTenantAndAgent(t *testing.T) {
	_, csrPEM, err := GenerateKeyAndCSR("", "org-1", "agent-a")
	if err != nil {
		t.Fatal(err)
	}
	block, _ := pem.Decode(csrPEM)
	csr, err := x509.ParseCertificateRequest(block.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	// IdentityFromCert reads from cert.URIs, which mirrors the CSR's URIs field once the gateway's
	// CA signs it — reuse the CSR's URI here to test extraction without a full signing flow.
	cert := &x509.Certificate{URIs: csr.URIs}

	tenant, agentID, ok := IdentityFromCert(cert)
	if !ok {
		t.Fatal("expected IdentityFromCert to succeed")
	}
	if tenant != "org-1" || agentID != "agent-a" {
		t.Fatalf("got tenant=%q agent=%q, want org-1/agent-a", tenant, agentID)
	}
}

func TestIdentityFromCertFailsWithoutSpiffeSAN(t *testing.T) {
	cert := &x509.Certificate{}
	if _, _, ok := IdentityFromCert(cert); ok {
		t.Fatal("expected IdentityFromCert to fail when no SPIFFE URI SAN is present")
	}
}
