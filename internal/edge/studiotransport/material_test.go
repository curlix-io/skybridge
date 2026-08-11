//go:build querystudio

package studiotransport

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"io"
	"log/slog"
	"math/big"
	"testing"
	"time"

	"github.com/curlix-io/skybridge/internal/certstore"
)

// expiredSelfSignedMaterialForTest mints a cert whose NotAfter is already in the past, to exercise
// ensureTLSMaterial's "cached cert present but expired" branch.
func expiredSelfSignedMaterialForTest(t *testing.T) (certPEM, keyPEM []byte) {
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
		Subject:               pkix.Name{CommonName: "expired-test"},
		NotBefore:             time.Now().Add(-48 * time.Hour),
		NotAfter:              time.Now().Add(-24 * time.Hour),
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

func TestTLSDirDefaultsWhenEmpty(t *testing.T) {
	c := &Client{cfg: Config{}}
	if got := c.tlsDir(); got != "/var/lib/skybridge/studio-tls" {
		t.Fatalf("expected default tls dir, got %q", got)
	}
}

func TestTLSDirUsesConfiguredValue(t *testing.T) {
	c := &Client{cfg: Config{TLSDir: "/custom/dir"}}
	if got := c.tlsDir(); got != "/custom/dir" {
		t.Fatalf("expected configured dir, got %q", got)
	}
}

func TestCertValidRejectsGarbage(t *testing.T) {
	if certValid(nil, 0) {
		t.Fatal("expected nil PEM to be invalid")
	}
	if certValid([]byte("not a pem"), 0) {
		t.Fatal("expected garbage PEM to be invalid")
	}
}

func TestCertValidAcceptsFreshCert(t *testing.T) {
	certPEM, _ := selfSignedMaterialForTest(t)
	if !certValid(certPEM, 0) {
		t.Fatal("expected a freshly minted cert to be valid with zero skew")
	}
}

func TestCertValidRejectsWhenSkewExceedsRemainingLife(t *testing.T) {
	certPEM, _ := selfSignedMaterialForTest(t)
	// selfSignedMaterialForTest mints a cert valid for 24h; a skew far beyond that pushes the
	// "renew by" threshold past the cert's actual expiry.
	if certValid(certPEM, 48*time.Hour) {
		t.Fatal("expected rejection when skew exceeds remaining validity")
	}
}

func TestEnsureTLSMaterialNoopWhenNothingConfigured(t *testing.T) {
	c := &Client{cfg: Config{}, logger: slog.New(slog.NewTextHandler(io.Discard, nil))}
	m, err := c.ensureTLSMaterial(context.Background())
	if err != nil || m != nil {
		t.Fatalf("expected (nil, nil) when no CA bundle and no TLSDir are set, got %v, %v", m, err)
	}
}

func TestEnsureTLSMaterialReusesValidCachedCert(t *testing.T) {
	dir := t.TempDir()
	certPEM, keyPEM := selfSignedMaterialForTest(t)
	store := certstore.FromEnv(dir, "")
	if err := store.Save(context.Background(), &certstore.Material{CABundlePEM: []byte("ca"), ClientCertPEM: certPEM, ClientKeyPEM: keyPEM}); err != nil {
		t.Fatal(err)
	}

	c := &Client{cfg: Config{TLSDir: dir}, logger: slog.New(slog.NewTextHandler(io.Discard, nil))}
	m, err := c.ensureTLSMaterial(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if m == nil || string(m.clientCertPEM) != string(certPEM) {
		t.Fatalf("expected the cached cert to be reused, got %v", m)
	}
	if string(m.caBundlePEM) != "ca" {
		t.Fatalf("expected the cached CA bundle to be preferred, got %q", m.caBundlePEM)
	}
}

func TestEnsureTLSMaterialNoCacheNoCANoTokenReturnsNil(t *testing.T) {
	dir := t.TempDir()
	c := &Client{cfg: Config{TLSDir: dir}, logger: slog.New(slog.NewTextHandler(io.Discard, nil))}
	m, err := c.ensureTLSMaterial(context.Background())
	if err != nil || m != nil {
		t.Fatalf("expected (nil, nil) with no cached cert, no CA bundle, and no enroll token, got %v, %v", m, err)
	}
}

func TestEnsureTLSMaterialNoCacheNoTokenErrorsWhenCAConfigured(t *testing.T) {
	dir := t.TempDir()
	c := &Client{cfg: Config{TLSDir: dir, CABundlePEM: []byte("ca-bundle")}, logger: slog.New(slog.NewTextHandler(io.Discard, nil))}
	_, err := c.ensureTLSMaterial(context.Background())
	if err == nil {
		t.Fatal("expected an error when a CA bundle is configured but there is no cached cert and no enroll token")
	}
}

func TestEnsureTLSMaterialExpiredCacheNoTokenReturnsCachedAnyway(t *testing.T) {
	dir := t.TempDir()
	certPEM, keyPEM := expiredSelfSignedMaterialForTest(t)
	store := certstore.FromEnv(dir, "")
	if err := store.Save(context.Background(), &certstore.Material{ClientCertPEM: certPEM, ClientKeyPEM: keyPEM}); err != nil {
		t.Fatal(err)
	}

	c := &Client{cfg: Config{TLSDir: dir, CABundlePEM: []byte("ca-bundle")}, logger: slog.New(slog.NewTextHandler(io.Discard, nil))}
	m, err := c.ensureTLSMaterial(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if m == nil || string(m.clientCertPEM) != string(certPEM) {
		t.Fatalf("expected the expired cached cert to be returned anyway, got %v", m)
	}
}
