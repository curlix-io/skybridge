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

func TestNewHTTPCredentialResolverDisabledWhenUnconfigured(t *testing.T) {
	if r := NewHTTPCredentialResolver(config.Agent{}); r != nil {
		t.Fatal("resolver should be nil when injection is off")
	}
	if r := NewHTTPCredentialResolver(config.Agent{InjectCredentials: true}); r != nil {
		t.Fatal("resolver should be nil without an exchange URL")
	}
}

func TestHTTPCredentialResolverExchange(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if got := r.Header.Get("Authorization"); got != "Bearer agent-secret" {
			http.Error(w, `{"detail":"unauthorized"}`, http.StatusUnauthorized)
			return
		}
		var body exchangeRequest
		_ = json.NewDecoder(r.Body).Decode(&body)
		if body.SessionToken != "tok-123" {
			http.Error(w, `{"detail":"bad token"}`, http.StatusForbidden)
			return
		}
		_ = json.NewEncoder(w).Encode(exchangeResponse{
			Username: "curlix_s_abc",
			Password: "mint3d",
			Database: body.RequestedDatabase,
		})
	}))
	defer srv.Close()

	resolve := NewHTTPCredentialResolver(config.Agent{
		InjectCredentials:       true,
		CredentialExchangeURL:   srv.URL,
		CredentialExchangeToken: "agent-secret",
	})
	if resolve == nil {
		t.Fatal("resolver should be configured")
	}

	cred, err := resolve(context.Background(), map[string]string{"user": "alice", "database": "appdb"}, "tok-123")
	if err != nil {
		t.Fatalf("exchange: %v", err)
	}
	if cred.Username != "curlix_s_abc" || cred.Password != "mint3d" || cred.Database != "appdb" {
		t.Fatalf("unexpected credential: %+v", cred)
	}
}

func TestHTTPCredentialResolverRejectsBadToken(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, `{"detail":"session token expired"}`, http.StatusForbidden)
	}))
	defer srv.Close()

	resolve := NewHTTPCredentialResolver(config.Agent{
		InjectCredentials:     true,
		CredentialExchangeURL: srv.URL,
	})
	_, err := resolve(context.Background(), map[string]string{}, "whatever")
	if err == nil || !strings.Contains(err.Error(), "session token expired") {
		t.Fatalf("expected rejection surfaced, got %v", err)
	}
}

func TestHTTPCredentialResolverEmptyToken(t *testing.T) {
	resolve := NewHTTPCredentialResolver(config.Agent{
		InjectCredentials:     true,
		CredentialExchangeURL: "http://127.0.0.1:0",
	})
	if _, err := resolve(context.Background(), map[string]string{}, "   "); err == nil {
		t.Fatal("expected error for an empty session token")
	}
}
