package agent

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

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

// TestHTTPCredentialResolverRateLimitsPerClientIP is the regression test for
// SKYBRIDGE_CREDENTIAL_EXCHANGE_PER_MIN: before it existed, a native client could open connections
// and try guessed session tokens as the password with nothing in this codebase slowing repeated
// failures down — one HTTP round trip to the control plane per attempt, unthrottled. The limited
// attempt must not even reach the server (asserted via a request counter).
func TestHTTPCredentialResolverRateLimitsPerClientIP(t *testing.T) {
	var requests int
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests++
		_ = json.NewEncoder(w).Encode(exchangeResponse{Username: "u", Password: "p"})
	}))
	defer srv.Close()

	resolve := NewHTTPCredentialResolver(config.Agent{
		InjectCredentials:        true,
		CredentialExchangeURL:    srv.URL,
		CredentialExchangePerMin: 1,
	})
	ctx := ContextWithWireClientIP(context.Background(), "203.0.113.9:1")

	if _, err := resolve(ctx, map[string]string{}, "tok-1"); err != nil {
		t.Fatalf("expected the first attempt to succeed, got %v", err)
	}
	if _, err := resolve(ctx, map[string]string{}, "tok-2"); !errors.Is(err, errCredentialExchangeRateLimited) {
		t.Fatalf("expected errCredentialExchangeRateLimited on the second attempt, got %v", err)
	}
	if requests != 1 {
		t.Fatalf("expected the rate-limited attempt to never reach the control plane, got %d requests", requests)
	}

	// A different client IP has its own independent budget.
	ctx2 := ContextWithWireClientIP(context.Background(), "198.51.100.1:1")
	if _, err := resolve(ctx2, map[string]string{}, "tok-3"); err != nil {
		t.Fatalf("expected a different client IP's first attempt to succeed, got %v", err)
	}
}

// TestHTTPCredentialResolverUnlimitedByDefault confirms the zero-value (CredentialExchangePerMin
// unset) stays fully unlimited — this is opt-in hardening, not a default behavior change.
func TestHTTPCredentialResolverUnlimitedByDefault(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(exchangeResponse{Username: "u", Password: "p"})
	}))
	defer srv.Close()

	resolve := NewHTTPCredentialResolver(config.Agent{
		InjectCredentials:     true,
		CredentialExchangeURL: srv.URL,
	})
	ctx := ContextWithWireClientIP(context.Background(), "203.0.113.9:1")
	for i := 0; i < 10; i++ {
		if _, err := resolve(ctx, map[string]string{}, "tok"); err != nil {
			t.Fatalf("attempt %d: expected no rate limit by default, got %v", i, err)
		}
	}
}

func TestCredExchangeLimiterAllowsUpToLimitThenBlocks(t *testing.T) {
	l := newCredExchangeLimiter(2)
	if !l.allow("ip-a") || !l.allow("ip-a") {
		t.Fatal("expected the first two attempts to be allowed")
	}
	if l.allow("ip-a") {
		t.Fatal("expected the third attempt within the window to be blocked")
	}
	// A different key has its own independent budget.
	if !l.allow("ip-b") {
		t.Fatal("expected a different key's first attempt to be allowed")
	}
}

func TestCredExchangeLimiterResetsAfterWindow(t *testing.T) {
	l := newCredExchangeLimiter(1)
	now := time.Now()
	l.now = func() time.Time { return now }

	if !l.allow("ip-a") {
		t.Fatal("expected the first attempt to be allowed")
	}
	if l.allow("ip-a") {
		t.Fatal("expected the second attempt within the same window to be blocked")
	}
	l.now = func() time.Time { return now.Add(time.Minute) }
	if !l.allow("ip-a") {
		t.Fatal("expected the window to reset after a minute")
	}
}

func TestNewCredExchangeLimiterNilWhenDisabled(t *testing.T) {
	if newCredExchangeLimiter(0) != nil {
		t.Fatal("expected nil limiter when limit <= 0")
	}
}

// TestNilCredExchangeLimiterAllowsEverything confirms a nil *credExchangeLimiter (what
// newCredExchangeLimiter returns when disabled) behaves as unlimited rather than panicking.
func TestNilCredExchangeLimiterAllowsEverything(t *testing.T) {
	var l *credExchangeLimiter
	for i := 0; i < 1000; i++ {
		if !l.allow("ip-a") {
			t.Fatal("expected a nil limiter to always allow")
		}
	}
}

func TestCredExchangeLimiterEmptyKeyAlwaysAllowed(t *testing.T) {
	l := newCredExchangeLimiter(1)
	l.allow("ip-a") // consume the one slot for a real key
	for i := 0; i < 5; i++ {
		if !l.allow("") {
			t.Fatal("expected an empty key (unknown client IP) to always be allowed")
		}
	}
}
