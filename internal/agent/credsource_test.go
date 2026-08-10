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
			Username: "skybridge_s_abc",
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
	if cred.Username != "skybridge_s_abc" || cred.Password != "mint3d" || cred.Database != "appdb" {
		t.Fatalf("unexpected credential: %+v", cred)
	}
}

func TestHTTPCredentialResolverSendsClientIP(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var body exchangeRequest
		_ = json.NewDecoder(r.Body).Decode(&body)
		if body.ClientIP != "203.0.113.9" {
			http.Error(w, `{"detail":"missing client ip"}`, http.StatusForbidden)
			return
		}
		_ = json.NewEncoder(w).Encode(exchangeResponse{Username: "u", Password: "p"})
	}))
	defer srv.Close()

	resolve := NewHTTPCredentialResolver(config.Agent{
		InjectCredentials:     true,
		CredentialExchangeURL: srv.URL,
	})
	ctx := ContextWithWireClientIP(context.Background(), "203.0.113.9:15432")
	if _, err := resolve(ctx, map[string]string{}, "tok"); err != nil {
		t.Fatal(err)
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

func TestHostFromTCPAddr(t *testing.T) {
	cases := map[string]string{
		"203.0.113.9:15432":   "203.0.113.9",
		"[::1]:15432":         "::1",
		"":                    "",
		"no-port-no-brackets": "no-port-no-brackets",
	}
	for addr, want := range cases {
		if got := hostFromTCPAddr(addr); got != want {
			t.Errorf("hostFromTCPAddr(%q) = %q, want %q", addr, got, want)
		}
	}
}

func TestContextWithWireClientIPEmptyAddrIsNoop(t *testing.T) {
	ctx := context.Background()
	got := ContextWithWireClientIP(ctx, "")
	if got != ctx {
		t.Fatal("expected the context to be returned unchanged for an empty address")
	}
	if ip := wireClientIPFromContext(got); ip != "" {
		t.Fatalf("expected no client IP set, got %q", ip)
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

func TestHTTPCredentialResolverBadJSONResponse(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte("not json"))
	}))
	defer srv.Close()

	resolve := NewHTTPCredentialResolver(config.Agent{
		InjectCredentials:     true,
		CredentialExchangeURL: srv.URL,
	})
	if _, err := resolve(context.Background(), map[string]string{}, "tok"); err == nil || !strings.Contains(err.Error(), "bad response") {
		t.Fatalf("expected a bad-response error, got %v", err)
	}
}

func TestHTTPCredentialResolverNoUsernameInResponse(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(w).Encode(exchangeResponse{})
	}))
	defer srv.Close()

	resolve := NewHTTPCredentialResolver(config.Agent{
		InjectCredentials:     true,
		CredentialExchangeURL: srv.URL,
	})
	if _, err := resolve(context.Background(), map[string]string{}, "tok"); err == nil || !strings.Contains(err.Error(), "no username") {
		t.Fatalf("expected a no-username error, got %v", err)
	}
}

func TestHTTPCredentialResolverDialFailure(t *testing.T) {
	resolve := NewHTTPCredentialResolver(config.Agent{
		InjectCredentials:     true,
		CredentialExchangeURL: "http://127.0.0.1:1",
	})
	if _, err := resolve(context.Background(), map[string]string{}, "tok"); err == nil || !strings.Contains(err.Error(), "credential exchange:") {
		t.Fatalf("expected a transport-level error, got %v", err)
	}
}
