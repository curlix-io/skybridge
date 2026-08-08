package wiremtls

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"math/big"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/curlix-io/skybridge/internal/certstore"
)

// generateExpiredCert mints a self-signed cert whose NotAfter is already in the past, to exercise
// EnsureMaterial's "cached cert present but expired" branch.
func generateExpiredCert(t *testing.T) (certPEM, keyPEM []byte, err error) {
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
		Subject:               pkix.Name{CommonName: "expired-test-cert"},
		NotBefore:             time.Now().Add(-48 * time.Hour),
		NotAfter:              time.Now().Add(-24 * time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		return nil, nil, err
	}
	keyDER, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return nil, nil, err
	}
	certPEM = pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	keyPEM = pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER})
	return certPEM, keyPEM, nil
}

func testServerCABundle(t *testing.T, srv *httptest.Server) []byte {
	t.Helper()
	cert := srv.Certificate()
	if cert == nil {
		t.Fatal("expected TLS test server to expose a certificate")
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: cert.Raw})
}

func TestEnsureMaterialNoCacheNoTokenFallsBackToNil(t *testing.T) {
	dir := t.TempDir()
	m, err := EnsureMaterial(context.Background(), EnrollConfig{TLSDir: dir, TenantID: "org-1", AgentID: "agent-a"})
	if err != nil {
		t.Fatal(err)
	}
	if m != nil {
		t.Fatalf("expected nil Material when no cert cached and no enroll token, got %v", m)
	}
}

func TestEnsureMaterialReusesValidCachedCert(t *testing.T) {
	dir := t.TempDir()
	cert, key, err := GenerateSelfSignedServerCert()
	if err != nil {
		t.Fatal(err)
	}
	store := certstore.FromEnv(dir, "")
	if err := store.Save(context.Background(), &certstore.Material{CABundlePEM: []byte("ca"), ClientCertPEM: cert, ClientKeyPEM: key}); err != nil {
		t.Fatal(err)
	}

	m, err := EnsureMaterial(context.Background(), EnrollConfig{TLSDir: dir, TenantID: "org-1", AgentID: "agent-a"})
	if err != nil {
		t.Fatal(err)
	}
	if m == nil || string(m.ClientCertPEM) != string(cert) || string(m.ClientKeyPEM) != string(key) {
		t.Fatalf("expected cached cert/key to be reused, got %v", m)
	}
	if string(m.CABundlePEM) != "ca" {
		t.Fatalf("expected cached CA bundle to be preferred, got %q", m.CABundlePEM)
	}
}

func TestEnsureMaterialExpiredCacheNoTokenReturnsCachedAnyway(t *testing.T) {
	dir := t.TempDir()
	cert, key, err := generateExpiredCert(t)
	if err != nil {
		t.Fatal(err)
	}
	if CertValid(cert, CertRenewSkew) {
		t.Fatal("test setup: expected this cert to already be expired")
	}
	store := certstore.FromEnv(dir, "")
	if err := store.Save(context.Background(), &certstore.Material{ClientCertPEM: cert, ClientKeyPEM: key}); err != nil {
		t.Fatal(err)
	}

	// No EnrollToken configured: EnsureMaterial can't renew, so it returns the expired material
	// anyway and lets the gateway reject it (see enroll.go's comment on this branch).
	m, err := EnsureMaterial(context.Background(), EnrollConfig{TLSDir: dir, TenantID: "org-1", AgentID: "agent-a"})
	if err != nil {
		t.Fatal(err)
	}
	if m == nil || string(m.ClientCertPEM) != string(cert) {
		t.Fatalf("expected the expired cached cert to be returned anyway, got %v", m)
	}
}

func TestEnsureMaterialEnrollsOverHTTPWhenTokenProvided(t *testing.T) {
	dir := t.TempDir()
	var gotBody map[string]string
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if err := json.NewDecoder(r.Body).Decode(&gotBody); err != nil {
			t.Errorf("decode request body: %v", err)
		}
		w.WriteHeader(http.StatusOK)
		_ = json.NewEncoder(w).Encode(map[string]string{
			"client_cert_pem": "issued-cert-pem",
			"ca_bundle_pem":   "issued-ca-pem",
		})
	}))
	defer srv.Close()

	m, err := EnsureMaterial(context.Background(), EnrollConfig{
		BaseURL:     srv.URL,
		TenantID:    "org-1",
		AgentID:     "agent-a",
		EnrollToken: "one-time-token",
		TLSDir:      dir,
		CABundlePEM: testServerCABundle(t, srv),
	})
	if err != nil {
		t.Fatal(err)
	}
	if m == nil || string(m.ClientCertPEM) != "issued-cert-pem" || string(m.CABundlePEM) != "issued-ca-pem" {
		t.Fatalf("unexpected material: %v", m)
	}
	if gotBody["enroll_token"] != "one-time-token" || gotBody["tenant_id"] != "org-1" || gotBody["agent_id"] != "agent-a" {
		t.Fatalf("unexpected request body: %v", gotBody)
	}
	if gotBody["csr_pem"] == "" {
		t.Fatal("expected a CSR PEM to be sent")
	}

	// The issued material should now be cached on disk for the next EnsureMaterial call.
	loaded, err := certstore.FromEnv(dir, "").Load(context.Background())
	if err != nil || loaded == nil || string(loaded.ClientCertPEM) != "issued-cert-pem" {
		t.Fatalf("expected issued material to be persisted, got %v err=%v", loaded, err)
	}
}

func TestEnsureMaterialFallsBackToConfiguredCABundleWhenResponseOmitsIt(t *testing.T) {
	dir := t.TempDir()
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_ = json.NewEncoder(w).Encode(map[string]string{"client_cert_pem": "issued-cert-pem"})
	}))
	defer srv.Close()
	caBundle := testServerCABundle(t, srv)

	m, err := EnsureMaterial(context.Background(), EnrollConfig{
		BaseURL:     srv.URL,
		TenantID:    "org-1",
		AgentID:     "agent-a",
		EnrollToken: "one-time-token",
		TLSDir:      dir,
		CABundlePEM: caBundle,
	})
	if err != nil {
		t.Fatal(err)
	}
	if string(m.CABundlePEM) != string(caBundle) {
		t.Fatal("expected configured CABundlePEM to be used when the response omits ca_bundle_pem")
	}
}

func TestEnsureMaterialReturnsErrorOnEnrollRejection(t *testing.T) {
	dir := t.TempDir()
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusForbidden)
		_ = json.NewEncoder(w).Encode(map[string]string{"detail": "token already used"})
	}))
	defer srv.Close()

	_, err := EnsureMaterial(context.Background(), EnrollConfig{
		BaseURL:     srv.URL,
		TenantID:    "org-1",
		AgentID:     "agent-a",
		EnrollToken: "one-time-token",
		TLSDir:      dir,
		CABundlePEM: testServerCABundle(t, srv),
	})
	if err == nil {
		t.Fatal("expected an error when the control plane rejects the enroll request")
	}
}

func TestEnsureMaterialUsesCustomPath(t *testing.T) {
	dir := t.TempDir()
	hit := false
	mux := http.NewServeMux()
	mux.HandleFunc("/custom/enroll", func(w http.ResponseWriter, r *http.Request) {
		hit = true
		w.WriteHeader(http.StatusOK)
		_ = json.NewEncoder(w).Encode(map[string]string{"client_cert_pem": "cert"})
	})
	srv := httptest.NewTLSServer(mux)
	defer srv.Close()

	_, err := EnsureMaterial(context.Background(), EnrollConfig{
		BaseURL:     srv.URL,
		Path:        "/custom/enroll",
		TenantID:    "org-1",
		AgentID:     "agent-a",
		EnrollToken: "tok",
		TLSDir:      dir,
		CABundlePEM: testServerCABundle(t, srv),
	})
	if err != nil {
		t.Fatal(err)
	}
	if !hit {
		t.Fatal("expected the custom enroll path to be hit")
	}
}

func TestTlsDirDefaultsWhenEmpty(t *testing.T) {
	got := tlsDir("")
	if got == "" {
		t.Fatal("expected a non-empty default tls dir")
	}
}

func TestTlsDirUsesConfiguredValue(t *testing.T) {
	if got := tlsDir("/custom/tls/dir"); got != "/custom/tls/dir" {
		t.Fatalf("expected configured dir to pass through unchanged, got %q", got)
	}
}
