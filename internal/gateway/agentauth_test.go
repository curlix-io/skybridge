package gateway_test

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/curlix-io/skybridge/internal/gateway"
)

func TestHTTPAgentAuthVerifierVerifiesKnownToken(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/verify-agent-token" {
			t.Fatalf("path=%s", r.URL.Path)
		}
		if r.Header.Get("Authorization") != "Bearer service-tok" {
			t.Fatalf("missing/incorrect service bearer: %s", r.Header.Get("Authorization"))
		}
		var body struct {
			Token string `json:"token"`
		}
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			t.Fatal(err)
		}
		if body.Token != "agent-tok" {
			t.Fatalf("token=%q", body.Token)
		}
		w.WriteHeader(http.StatusOK)
		_ = json.NewEncoder(w).Encode(map[string]any{
			"ok":              true,
			"organization_id": "org-1",
			"connector_id":    "conn-1",
		})
	}))
	defer srv.Close()

	v := gateway.NewHTTPAgentAuthVerifier(srv.URL, "/verify-agent-token", "service-tok")
	tenantID, agentID, ok := v.Verify(context.Background(), "agent-tok")
	if !ok || tenantID != "org-1" || agentID != "conn-1" {
		t.Fatalf("got tenantID=%q agentID=%q ok=%v", tenantID, agentID, ok)
	}
}

func TestHTTPAgentAuthVerifierUnknownTokenReturnsFalse(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		_ = json.NewEncoder(w).Encode(map[string]any{"ok": false})
	}))
	defer srv.Close()

	v := gateway.NewHTTPAgentAuthVerifier(srv.URL, "", "service-tok")
	_, _, ok := v.Verify(context.Background(), "unknown-tok")
	if ok {
		t.Fatal("expected ok=false for an unrecognized token")
	}
}

func TestHTTPAgentAuthVerifierHTTPErrorFailsClosed(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
	}))
	defer srv.Close()

	v := gateway.NewHTTPAgentAuthVerifier(srv.URL, "", "service-tok")
	_, _, ok := v.Verify(context.Background(), "agent-tok")
	if ok {
		t.Fatal("expected ok=false on a non-2xx control-plane response")
	}
}

func TestHTTPAgentAuthVerifierEmptyTokenNeverCallsControlPlane(t *testing.T) {
	called := false
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		called = true
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	v := gateway.NewHTTPAgentAuthVerifier(srv.URL, "", "service-tok")
	_, _, ok := v.Verify(context.Background(), "")
	if ok {
		t.Fatal("expected ok=false for an empty token")
	}
	if called {
		t.Fatal("expected no control-plane call for an empty token")
	}
}

func TestNoopAgentAuthVerifierAlwaysFailsClosed(t *testing.T) {
	var v gateway.NoopAgentAuthVerifier
	_, _, ok := v.Verify(context.Background(), "anything")
	if ok {
		t.Fatal("NoopAgentAuthVerifier must always return ok=false")
	}
}
