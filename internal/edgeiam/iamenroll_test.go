package edgeiam

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// setStaticAWSCreds makes PresignGetCallerIdentity deterministic in CI, where there's no ambient
// IMDS/task role to satisfy the SDK's default credential chain. Presigning only needs *some*
// static credentials to sign against — it never calls STS over the network.
func setStaticAWSCreds(t *testing.T) {
	t.Helper()
	t.Setenv("AWS_ACCESS_KEY_ID", "test-access-key-id")
	t.Setenv("AWS_SECRET_ACCESS_KEY", "test-secret-access-key")
	t.Setenv("AWS_REGION", "us-west-2")
}

func TestEnrollTokenViaIAM_RequestBodyHasExpectedFields(t *testing.T) {
	setStaticAWSCreds(t)
	var captured map[string]any
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if err := json.NewDecoder(r.Body).Decode(&captured); err != nil {
			t.Errorf("decode request body: %v", err)
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"enroll_token":"tok-123"}`))
	}))
	defer srv.Close()

	token, err := EnrollTokenViaIAM(context.Background(), IamEnrollConfig{
		BaseURL:  srv.URL,
		Path:     "/api/v1/skybridge/wire-mtls/enroll-token-iam",
		TenantID: "org-1",
		AgentID:  "agent-a",
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if token != "tok-123" {
		t.Fatalf("expected token %q, got %q", "tok-123", token)
	}

	for _, key := range []string{"tenant_id", "agent_id", "sts_method", "sts_url", "sts_headers"} {
		if _, ok := captured[key]; !ok {
			t.Errorf("expected field %q in request body, got %v", key, captured)
		}
	}
	if captured["tenant_id"] != "org-1" || captured["agent_id"] != "agent-a" {
		t.Errorf("unexpected tenant_id/agent_id in request body: %v", captured)
	}
}

func TestEnrollTokenViaIAM_MergesExtraFields(t *testing.T) {
	setStaticAWSCreds(t)
	var captured map[string]any
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewDecoder(r.Body).Decode(&captured)
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"enrollment_token":"tok-456"}`))
	}))
	defer srv.Close()

	token, err := EnrollTokenViaIAM(context.Background(), IamEnrollConfig{
		BaseURL:  srv.URL,
		Path:     "/api/v1/skybridge/enrollments-iam",
		TenantID: "org-1",
		AgentID:  "connector-a",
		Extra:    map[string]string{"studio_agent_id": "studio-a"},
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if token != "tok-456" {
		t.Fatalf("expected token %q, got %q", "tok-456", token)
	}
	if captured["studio_agent_id"] != "studio-a" {
		t.Errorf("expected studio_agent_id to be merged into request body, got %v", captured)
	}
}

func TestEnrollTokenViaIAM_LoadAWSConfigError(t *testing.T) {
	// A profile that doesn't exist in the (real or absent) shared config file makes
	// awsconfig.LoadDefaultConfig fail deterministically, exercising the "load AWS config" error
	// path without needing network access.
	t.Setenv("AWS_ACCESS_KEY_ID", "")
	t.Setenv("AWS_SECRET_ACCESS_KEY", "")
	t.Setenv("AWS_PROFILE", "definitely-not-a-real-profile-xyz")
	t.Setenv("AWS_SDK_LOAD_CONFIG", "1")
	dir := t.TempDir()
	t.Setenv("AWS_CONFIG_FILE", dir+"/config")
	t.Setenv("AWS_SHARED_CREDENTIALS_FILE", dir+"/credentials")

	_, err := EnrollTokenViaIAM(context.Background(), IamEnrollConfig{
		BaseURL: "https://example.invalid",
		Path:    "/enroll",
	})
	if err == nil {
		t.Fatal("expected an error when the AWS config/profile cannot be loaded")
	}
}

func TestEnrollTokenViaIAM_PresignErrorWithoutRegion(t *testing.T) {
	// Static credentials with no region configured anywhere make PresignGetCallerIdentity fail
	// while never making a real network call — presigning is purely local computation that still
	// needs a region to build the STS endpoint.
	t.Setenv("AWS_ACCESS_KEY_ID", "test-access-key-id")
	t.Setenv("AWS_SECRET_ACCESS_KEY", "test-secret-access-key")
	t.Setenv("AWS_REGION", "")
	t.Setenv("AWS_DEFAULT_REGION", "")
	t.Setenv("AWS_PROFILE", "")
	t.Setenv("AWS_SDK_LOAD_CONFIG", "")
	dir := t.TempDir()
	t.Setenv("AWS_CONFIG_FILE", dir+"/config")
	t.Setenv("AWS_SHARED_CREDENTIALS_FILE", dir+"/credentials")

	_, err := EnrollTokenViaIAM(context.Background(), IamEnrollConfig{
		BaseURL: "https://example.invalid",
		Path:    "/enroll",
	})
	if err == nil {
		t.Fatal("expected a presign error when no region is configured")
	}
}

func TestEnrollTokenViaIAM_HTTPDoErrorOnUnreachableServer(t *testing.T) {
	setStaticAWSCreds(t)
	// Port 0 dialed directly never succeeds; using an httptest server then closing it immediately
	// gives a stable "connection refused" target without relying on a specific unused port number.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	srv.Close()

	_, err := EnrollTokenViaIAM(context.Background(), IamEnrollConfig{
		BaseURL: srv.URL,
		Path:    "/enroll",
	})
	if err == nil {
		t.Fatal("expected an error when the control plane is unreachable")
	}
}

func TestEnrollTokenViaIAM_NonSuccessStatusUsesJSONDetail(t *testing.T) {
	setStaticAWSCreds(t)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusBadRequest)
		_, _ = w.Write([]byte(`{"detail":"tenant not found"}`))
	}))
	defer srv.Close()

	_, err := EnrollTokenViaIAM(context.Background(), IamEnrollConfig{
		BaseURL:  srv.URL,
		Path:     "/enroll",
		TenantID: "org-1",
		AgentID:  "agent-a",
	})
	if err == nil {
		t.Fatal("expected an error on non-2xx response")
	}
	if !strings.Contains(err.Error(), "tenant not found") {
		t.Fatalf("expected error to include JSON detail, got %v", err)
	}
}

func TestEnrollTokenViaIAM_NonSuccessStatusFallsBackToRawBody(t *testing.T) {
	setStaticAWSCreds(t)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
		_, _ = w.Write([]byte("internal server error, not json"))
	}))
	defer srv.Close()

	_, err := EnrollTokenViaIAM(context.Background(), IamEnrollConfig{
		BaseURL:  srv.URL,
		Path:     "/enroll",
		TenantID: "org-1",
		AgentID:  "agent-a",
	})
	if err == nil {
		t.Fatal("expected an error on non-2xx response")
	}
	if !strings.Contains(err.Error(), "internal server error, not json") {
		t.Fatalf("expected error to fall back to raw body, got %v", err)
	}
}

func TestEnrollTokenViaIAM_EmptyTokenInResponse(t *testing.T) {
	setStaticAWSCreds(t)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{}`))
	}))
	defer srv.Close()

	_, err := EnrollTokenViaIAM(context.Background(), IamEnrollConfig{
		BaseURL:  srv.URL,
		Path:     "/enroll",
		TenantID: "org-1",
		AgentID:  "agent-a",
	})
	if err == nil {
		t.Fatal("expected an error when response has neither enroll_token nor enrollment_token")
	}
	if !strings.Contains(err.Error(), "empty token") {
		t.Fatalf("expected empty-token error, got %v", err)
	}
}
