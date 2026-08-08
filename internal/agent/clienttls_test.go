package agent

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"log"
	"math/big"
	"testing"
	"time"

	"github.com/curlix-io/skybridge/internal/config"
)

func TestBuildClientTLSConfigDisabledByDefault(t *testing.T) {
	cfg, err := buildClientTLSConfig(config.Agent{}, nil)
	if err != nil || cfg != nil {
		t.Fatalf("expected (nil, nil) when nothing is configured, got %v, %v", cfg, err)
	}
}

func TestBuildClientTLSConfigFromCertAndKey(t *testing.T) {
	certPEM, keyPEM, err := selfSignedCertPEMForTest(t)
	if err != nil {
		t.Fatal(err)
	}
	cfg, err := buildClientTLSConfig(config.Agent{ClientTLSCertPEM: certPEM, ClientTLSKeyPEM: keyPEM}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if cfg == nil || len(cfg.Certificates) != 1 {
		t.Fatalf("expected a configured cert, got %v", cfg)
	}
}

func TestBuildClientTLSConfigRejectsMismatchedCertAndKey(t *testing.T) {
	certPEM, _, err := selfSignedCertPEMForTest(t)
	if err != nil {
		t.Fatal(err)
	}
	_, keyPEM2, err := selfSignedCertPEMForTest(t)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := buildClientTLSConfig(config.Agent{ClientTLSCertPEM: certPEM, ClientTLSKeyPEM: keyPEM2}, nil); err == nil {
		t.Fatal("expected an error for a mismatched cert/key pair")
	}
}

func TestBuildClientTLSConfigSelfSignedWarns(t *testing.T) {
	var buf bytes.Buffer
	cfg, err := buildClientTLSConfig(config.Agent{ClientTLSSelfSigned: true}, log.New(&buf, "", 0))
	if err != nil {
		t.Fatal(err)
	}
	if cfg == nil || len(cfg.Certificates) != 1 {
		t.Fatalf("expected a self-signed cert to be generated, got %v", cfg)
	}
	if !bytes.Contains(buf.Bytes(), []byte("EPHEMERAL self-signed")) {
		t.Fatalf("expected a self-signed warning, got %q", buf.String())
	}
}

func TestGenerateSelfSignedCertProducesUsablePair(t *testing.T) {
	cert, err := generateSelfSignedCert()
	if err != nil {
		t.Fatal(err)
	}
	if len(cert.Certificate) == 0 {
		t.Fatal("expected at least one certificate in the chain")
	}
}

func TestEngineFactoryPlaintext(t *testing.T) {
	factory := engineFactory(nil, "")
	cases := map[string]string{"postgres": "postgres", "postgresql": "postgres", "mysql": "mysql", "mongodb": "mongodb", "mongo": "mongodb"}
	for in, wantName := range cases {
		e, err := factory(in)
		if err != nil {
			t.Fatalf("factory(%q): %v", in, err)
		}
		if e.Name() != wantName {
			t.Errorf("factory(%q).Name() = %q, want %q", in, e.Name(), wantName)
		}
	}
	if _, err := factory("oracle"); err == nil {
		t.Fatal("expected an error for an unsupported db type")
	}
}

func TestEngineFactoryWithClientTLSForPostgresAndMySQL(t *testing.T) {
	tlsCfg := agentTestTLSConfig(t)
	factory := engineFactory(tlsCfg, "")
	pg, err := factory("postgres")
	if err != nil {
		t.Fatal(err)
	}
	if pg.Name() != "postgres" {
		t.Fatalf("expected a postgres engine, got %v", pg)
	}
	my, err := factory("mysql")
	if err != nil {
		t.Fatal(err)
	}
	if my.Name() != "mysql" {
		t.Fatalf("expected a mysql engine, got %v", my)
	}
	// Mongo does not yet terminate client TLS, so it ignores clientTLS entirely.
	mo, err := factory("mongodb")
	if err != nil {
		t.Fatal(err)
	}
	if mo.Name() != "mongodb" {
		t.Fatalf("expected a mongodb engine, got %v", mo)
	}
}

// selfSignedCertPEMForTest returns PEM-encoded cert/key bytes for building an agent client TLS config.
func selfSignedCertPEMForTest(t *testing.T) (certPEM, keyPEM []byte, err error) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, nil, err
	}
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return nil, nil, err
	}
	tmpl := &x509.Certificate{
		SerialNumber:          serial,
		Subject:               pkix.Name{CommonName: "test-cert"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		return nil, nil, err
	}
	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		return nil, nil, err
	}
	certPEM = pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	keyPEM = pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})
	return certPEM, keyPEM, nil
}
