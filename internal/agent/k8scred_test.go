package agent

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/curlix-io/skybridge/internal/config"
)

func TestNewHTTPK8sCredentialResolverNilWhenUnconfigured(t *testing.T) {
	if r := NewHTTPK8sCredentialResolver(config.Agent{}); r != nil {
		t.Fatal("resolver should be nil without an exchange URL")
	}
}

func TestHTTPK8sCredentialResolverExchange(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if got := r.Header.Get("Authorization"); got != "Bearer agent-secret" {
			http.Error(w, `{"detail":"unauthorized"}`, http.StatusUnauthorized)
			return
		}
		var body k8sExchangeRequest
		_ = json.NewDecoder(r.Body).Decode(&body)
		if body.SessionToken != "tok-123" {
			http.Error(w, `{"detail":"bad token"}`, http.StatusForbidden)
			return
		}
		_ = json.NewEncoder(w).Encode(k8sExchangeResponse{
			BearerToken: "cluster-bearer",
			CACertPEM:   "-----BEGIN CERTIFICATE-----\nabc\n-----END CERTIFICATE-----",
		})
	}))
	defer srv.Close()

	resolve := NewHTTPK8sCredentialResolver(config.Agent{
		K8sCredentialExchangeURL: srv.URL,
		CredentialExchangeToken:  "agent-secret",
	})
	if resolve == nil {
		t.Fatal("resolver should be configured")
	}
	cred, err := resolve(context.Background(), "tok-123")
	if err != nil {
		t.Fatalf("exchange: %v", err)
	}
	if cred.BearerToken != "cluster-bearer" || len(cred.CACertPEM) == 0 {
		t.Fatalf("unexpected credential: %+v", cred)
	}
}

func TestHTTPK8sCredentialResolverEmptyToken(t *testing.T) {
	resolve := NewHTTPK8sCredentialResolver(config.Agent{K8sCredentialExchangeURL: "http://127.0.0.1:0"})
	if _, err := resolve(context.Background(), "   "); err == nil {
		t.Fatal("expected an error for an empty session token")
	}
}

func TestHTTPK8sCredentialResolverRejectsBadToken(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		http.Error(w, `{"detail":"session token expired"}`, http.StatusForbidden)
	}))
	defer srv.Close()

	resolve := NewHTTPK8sCredentialResolver(config.Agent{K8sCredentialExchangeURL: srv.URL})
	_, err := resolve(context.Background(), "whatever")
	if err == nil || !strings.Contains(err.Error(), "session token expired") {
		t.Fatalf("expected rejection surfaced, got %v", err)
	}
}

func TestHTTPK8sCredentialResolverNoBearerTokenInResponse(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(w).Encode(k8sExchangeResponse{})
	}))
	defer srv.Close()

	resolve := NewHTTPK8sCredentialResolver(config.Agent{K8sCredentialExchangeURL: srv.URL})
	if _, err := resolve(context.Background(), "tok"); err == nil || !strings.Contains(err.Error(), "no bearer token") {
		t.Fatalf("expected a no-bearer-token error, got %v", err)
	}
}

func TestHTTPK8sCredentialResolverBadJSONResponse(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte("not json"))
	}))
	defer srv.Close()

	resolve := NewHTTPK8sCredentialResolver(config.Agent{K8sCredentialExchangeURL: srv.URL})
	if _, err := resolve(context.Background(), "tok"); err == nil || !strings.Contains(err.Error(), "bad response") {
		t.Fatalf("expected a bad-response error, got %v", err)
	}
}

func TestHTTPK8sCredentialResolverDialFailure(t *testing.T) {
	resolve := NewHTTPK8sCredentialResolver(config.Agent{K8sCredentialExchangeURL: "http://127.0.0.1:1"})
	if _, err := resolve(context.Background(), "tok"); err == nil || !strings.Contains(err.Error(), "k8s credential exchange:") {
		t.Fatalf("expected a transport-level error, got %v", err)
	}
}

func TestHTTPK8sCredentialResolverSendsAuthAndCACert(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if got := r.Header.Get("Authorization"); got != "" {
			t.Errorf("expected no Authorization header when no exchange token is configured, got %q", got)
		}
		_ = json.NewEncoder(w).Encode(k8sExchangeResponse{BearerToken: "b", InsecureSkipVerify: true})
	}))
	defer srv.Close()

	resolve := NewHTTPK8sCredentialResolver(config.Agent{K8sCredentialExchangeURL: srv.URL})
	cred, err := resolve(context.Background(), "tok")
	if err != nil {
		t.Fatal(err)
	}
	if !cred.InsecureSkipVerify || len(cred.CACertPEM) != 0 {
		t.Fatalf("unexpected credential: %+v", cred)
	}
}
