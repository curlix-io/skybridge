package agent

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/curlix-io/skybridge/internal/config"
)

func TestReportListenerCertNoopWithoutURL(t *testing.T) {
	// Must not panic or block when unconfigured — this is called fire-and-forget from a goroutine.
	reportListenerCert(context.Background(), config.Agent{}, "postgres", []byte("cert"), nil)
}

func TestReportListenerCertNoopWithoutCert(t *testing.T) {
	reportListenerCert(context.Background(), config.Agent{ListenerCertReportURL: "http://example.invalid", OrgID: "org-1"}, "postgres", nil, nil)
}

func TestReportListenerCertPostsBodyWithBearer(t *testing.T) {
	var gotAuth string
	var gotBody listenerCertReportRequest
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		gotAuth = req.Header.Get("Authorization")
		_ = json.NewDecoder(req.Body).Decode(&gotBody)
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	reportListenerCert(context.Background(), config.Agent{
		ListenerCertReportURL:   srv.URL,
		OrgID:                   "org-1",
		CredentialExchangeToken: "tok-abc",
	}, "kubernetes", []byte("PEM-DATA"), nil)

	if gotAuth != "Bearer tok-abc" {
		t.Fatalf("expected bearer token, got %q", gotAuth)
	}
	if gotBody.OrganizationID != "org-1" || gotBody.Driver != "kubernetes" || gotBody.CertPEM != "PEM-DATA" {
		t.Fatalf("unexpected report body: %+v", gotBody)
	}
}

func TestReportListenerCertSkipsWithoutOrgID(t *testing.T) {
	called := false
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		called = true
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	reportListenerCert(context.Background(), config.Agent{ListenerCertReportURL: srv.URL}, "postgres", []byte("cert"), nil)
	if called {
		t.Fatal("expected no request to be sent without an org id")
	}
}

func TestReportListenerCertLogsButDoesNotPanicOnRejection(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		w.WriteHeader(http.StatusForbidden)
		_, _ = w.Write([]byte(`{"detail":"nope"}`))
	}))
	defer srv.Close()

	reportListenerCert(context.Background(), config.Agent{
		ListenerCertReportURL: srv.URL,
		OrgID:                 "org-1",
	}, "postgres", []byte("cert"), nil)
}
