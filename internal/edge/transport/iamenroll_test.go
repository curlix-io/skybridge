package transport

import (
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

// setStaticAWSCreds makes PresignGetCallerIdentity deterministic in CI, where there's no ambient
// IMDS/task role to satisfy the SDK's default credential chain — mirrors
// internal/edgeiam's iamenroll_test.go helper.
func setStaticAWSCreds(t *testing.T) {
	t.Helper()
	t.Setenv("AWS_ACCESS_KEY_ID", "test-access-key-id")
	t.Setenv("AWS_SECRET_ACCESS_KEY", "test-secret-access-key")
	t.Setenv("AWS_REGION", "us-west-2")
}

func TestEnsureTLSMaterialIamAuthMintsTokenThenEnrolls(t *testing.T) {
	setStaticAWSCreds(t)
	ca := newTestCA(t)
	target, stopGW := startTLSGRPCServer(t, ca, &fakeEnrollGateway{ca: ca})
	defer stopGW()

	var captured map[string]any
	iamSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != DefaultIamEnrollTokenPath {
			t.Errorf("unexpected IAM enroll path: %s", r.URL.Path)
		}
		_ = json.NewDecoder(r.Body).Decode(&captured)
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"enroll_token":"iam-minted-token"}`))
	}))
	defer iamSrv.Close()

	c := New(Config{
		Target:         target,
		TenantID:       "org-1",
		ConnectorID:    "edge-1",
		CABundlePEM:    ca.certPEM,
		TLSDir:         t.TempDir(),
		IamAuthEnabled: true,
		IamEnrollURL:   iamSrv.URL,
	}, nil, slog.New(slog.NewTextHandler(io.Discard, nil)))

	m, err := c.ensureTLSMaterial(context.Background())
	if err != nil {
		t.Fatalf("ensureTLSMaterial: %v", err)
	}
	if m == nil || len(m.clientCertPEM) == 0 {
		t.Fatal("expected material minted via IAM-authenticated enroll")
	}
	if captured["tenant_id"] != "org-1" || captured["agent_id"] != "edge-1" {
		t.Errorf("unexpected tenant_id/agent_id sent to IAM enroll-token endpoint: %v", captured)
	}
}

func TestEnsureTLSMaterialIamAuthMintFailureReusesStale(t *testing.T) {
	setStaticAWSCreds(t)
	ca := newTestCA(t)
	keyPEM, csrPEM, err := generateKeyAndCSR("", "org-1", "edge-1")
	if err != nil {
		t.Fatalf("generate: %v", err)
	}
	certPEM := ca.sign(t, csrPEM, "org-1", "edge-1", time.Now().Add(10*time.Minute))

	dir := t.TempDir()
	mustWrite(t, dir+"/ca.pem", ca.certPEM)
	mustWrite(t, dir+"/client.crt", certPEM)
	mustWrite(t, dir+"/client.key", keyPEM)

	iamSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer iamSrv.Close()

	c := New(Config{
		TenantID:       "org-1",
		ConnectorID:    "edge-1",
		CABundlePEM:    ca.certPEM,
		TLSDir:         dir,
		IamAuthEnabled: true,
		IamEnrollURL:   iamSrv.URL,
	}, nil, slog.New(slog.NewTextHandler(io.Discard, nil)))

	m, err := c.ensureTLSMaterial(context.Background())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if m == nil || string(m.clientCertPEM) != string(certPEM) {
		t.Fatal("expected stale cached material to be reused when the IAM mint fails")
	}
}

func TestEnsureTLSMaterialIamAuthMintFailureNoStaleErrors(t *testing.T) {
	setStaticAWSCreds(t)
	ca := newTestCA(t)
	iamSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer iamSrv.Close()

	c := New(Config{
		TenantID:       "org-1",
		ConnectorID:    "edge-1",
		CABundlePEM:    ca.certPEM,
		TLSDir:         t.TempDir(),
		IamAuthEnabled: true,
		IamEnrollURL:   iamSrv.URL,
	}, nil, slog.New(slog.NewTextHandler(io.Discard, nil)))

	if _, err := c.ensureTLSMaterial(context.Background()); err == nil {
		t.Fatal("expected error when the IAM mint fails and there is no cached material to fall back on")
	}
}

func TestEnsureTLSMaterialIamAuthSkipsMintWhenCachedCertValid(t *testing.T) {
	setStaticAWSCreds(t)
	ca := newTestCA(t)
	keyPEM, csrPEM, err := generateKeyAndCSR("", "org-1", "edge-1")
	if err != nil {
		t.Fatalf("generate: %v", err)
	}
	certPEM := ca.sign(t, csrPEM, "org-1", "edge-1", time.Now().Add(24*time.Hour))

	dir := t.TempDir()
	mustWrite(t, dir+"/ca.pem", ca.certPEM)
	mustWrite(t, dir+"/client.crt", certPEM)
	mustWrite(t, dir+"/client.key", keyPEM)

	called := false
	iamSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		called = true
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer iamSrv.Close()

	c := New(Config{
		TenantID:       "org-1",
		ConnectorID:    "edge-1",
		CABundlePEM:    ca.certPEM,
		TLSDir:         dir,
		IamAuthEnabled: true,
		IamEnrollURL:   iamSrv.URL,
	}, nil, slog.New(slog.NewTextHandler(io.Discard, nil)))

	m, err := c.ensureTLSMaterial(context.Background())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if m == nil || string(m.clientCertPEM) != string(certPEM) {
		t.Fatal("expected cached, still-valid cert to be reused")
	}
	if called {
		t.Fatal("should not have called the IAM enroll-token endpoint when a valid cert is cached")
	}
}
