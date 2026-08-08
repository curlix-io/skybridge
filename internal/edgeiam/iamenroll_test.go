package edgeiam

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestEnrollTokenViaIAM_RequestBodyHasExpectedFields(t *testing.T) {
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
