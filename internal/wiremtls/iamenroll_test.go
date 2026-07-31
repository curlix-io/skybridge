package wiremtls

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/curlix-io/skybridge/internal/certstore"
)

func TestEnsureMaterialViaIAM_ReusesCachedCertWithoutReenrolling(t *testing.T) {
	dir := t.TempDir()
	cert, key, err := GenerateSelfSignedServerCert()
	if err != nil {
		t.Fatal(err)
	}
	store := certstore.FromEnv(dir, "")
	if err := store.Save(context.Background(), &certstore.Material{ClientCertPEM: cert, ClientKeyPEM: key}); err != nil {
		t.Fatal(err)
	}

	called := false
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		called = true
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer srv.Close()

	m, err := EnsureMaterialViaIAM(
		context.Background(),
		IamEnrollConfig{BaseURL: srv.URL, TenantID: "org-1", AgentID: "agent-a"},
		EnrollConfig{TLSDir: dir, TenantID: "org-1", AgentID: "agent-a"},
	)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if m == nil || string(m.ClientCertPEM) != string(cert) {
		t.Fatalf("expected cached cert to be reused")
	}
	if called {
		t.Fatalf("should not have called the IAM enroll-token endpoint when a valid cert is cached")
	}
}

func TestIamEnrollTokenRequestBody_MarshalsExpectedFields(t *testing.T) {
	body, err := json.Marshal(iamEnrollTokenRequestBody{
		TenantID:   "org-1",
		AgentID:    "agent-a",
		StsMethod:  "GET",
		StsURL:     "https://sts.amazonaws.com/?Action=GetCallerIdentity",
		StsHeaders: map[string]string{"Authorization": "AWS4-HMAC-SHA256 ..."},
	})
	if err != nil {
		t.Fatal(err)
	}
	var out map[string]any
	if err := json.Unmarshal(body, &out); err != nil {
		t.Fatal(err)
	}
	for _, key := range []string{"tenant_id", "agent_id", "sts_method", "sts_url", "sts_headers"} {
		if _, ok := out[key]; !ok {
			t.Errorf("expected field %q in marshaled body", key)
		}
	}
}
