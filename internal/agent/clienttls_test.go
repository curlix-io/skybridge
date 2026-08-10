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
	factory := engineFactory(nil, "", nil)
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

func TestEngineFactoryWithClientTLSForPostgresMySQLAndMongo(t *testing.T) {
	tlsCfg := agentTestTLSConfig(t)
	factory := engineFactory(tlsCfg, "", nil)
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
	// Mongo now terminates client TLS too (see internal/wire/mongo.NewWithClientTLS).
	mo, err := factory("mongodb")
	if err != nil {
		t.Fatal(err)
	}
	if mo.Name() != "mongodb" {
		t.Fatalf("expected a mongodb engine, got %v", mo)
	}
}

func TestEngineFactoryWithPostgresCatalogResolver(t *testing.T) {
	r, err := buildPostgresCatalogResolver(config.Agent{PostgresCatalogDSN: "postgres://db.internal:5432/postgres"})
	if err != nil {
		t.Fatal(err)
	}
	factory := engineFactory(nil, "org-1", r)
	pg, err := factory("postgres")
	if err != nil {
		t.Fatal(err)
	}
	if pg.Name() != "postgres" {
		t.Fatalf("expected a postgres engine wired with the catalog resolver, got %v", pg)
	}
}

func TestLogPostgresCatalogModeDefaultsNilLogger(t *testing.T) {
	// A nil logger must fall back to log.Default() rather than panic.
	r, err := buildPostgresCatalogResolver(config.Agent{PostgresCatalogDSN: "postgres://db.internal:5432/postgres"})
	if err != nil {
		t.Fatal(err)
	}
	logPostgresCatalogMode(config.Agent{}, r, nil)
}

func TestBuildPostgresCatalogResolverNilWhenUnconfigured(t *testing.T) {
	r, err := buildPostgresCatalogResolver(config.Agent{})
	if err != nil || r != nil {
		t.Fatalf("expected (nil, nil) when SKYBRIDGE_POSTGRES_CATALOG_DSN is unset, got %v, %v", r, err)
	}
}

func TestBuildPostgresCatalogResolverRejectsBadDSN(t *testing.T) {
	if _, err := buildPostgresCatalogResolver(config.Agent{PostgresCatalogDSN: "not-a-dsn"}); err == nil {
		t.Fatal("expected an error for a malformed catalog DSN")
	}
}

func TestBuildPostgresCatalogResolverFromValidDSN(t *testing.T) {
	r, err := buildPostgresCatalogResolver(config.Agent{PostgresCatalogDSN: "postgres://user:pass@db.internal:5432/postgres"})
	if err != nil {
		t.Fatal(err)
	}
	if r == nil {
		t.Fatal("expected a configured catalog resolver")
	}
}

func TestLogPostgresCatalogModeNoopWhenNil(t *testing.T) {
	var buf bytes.Buffer
	logPostgresCatalogMode(config.Agent{}, nil, log.New(&buf, "", 0))
	if buf.Len() != 0 {
		t.Fatalf("expected no output when resolver is nil, got %q", buf.String())
	}
}

func TestLogPostgresCatalogModeNotesMissingPathLabelURL(t *testing.T) {
	r, err := buildPostgresCatalogResolver(config.Agent{PostgresCatalogDSN: "postgres://db.internal:5432/postgres"})
	if err != nil {
		t.Fatal(err)
	}
	var buf bytes.Buffer
	logPostgresCatalogMode(config.Agent{}, r, log.New(&buf, "", 0))
	out := buf.String()
	if !bytes.Contains(buf.Bytes(), []byte("ENABLED")) {
		t.Fatalf("expected an enabled message, got %q", out)
	}
	if !bytes.Contains(buf.Bytes(), []byte("SKYBRIDGE_PATH_LABEL_URL is not set")) {
		t.Fatalf("expected a note about PathOverlay not being wired in, got %q", out)
	}
}

func TestLogPostgresCatalogModeSilentNoteWhenPathLabelConfigured(t *testing.T) {
	r, err := buildPostgresCatalogResolver(config.Agent{PostgresCatalogDSN: "postgres://db.internal:5432/postgres"})
	if err != nil {
		t.Fatal(err)
	}
	var buf bytes.Buffer
	logPostgresCatalogMode(config.Agent{PathLabelURL: "https://cp.example.com"}, r, log.New(&buf, "", 0))
	if bytes.Contains(buf.Bytes(), []byte("is not set")) {
		t.Fatalf("expected no missing-path-label note, got %q", buf.String())
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
