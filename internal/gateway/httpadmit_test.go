package gateway_test

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/curlix-io/skybridge/internal/gateway"
)

func TestHTTPWireAdmitterAllows(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/wire-admit" {
			t.Fatalf("path=%s", r.URL.Path)
		}
		var body struct {
			OrganizationID string `json:"organization_id"`
			ClientIP       string `json:"client_ip"`
		}
		_ = json.NewDecoder(r.Body).Decode(&body)
		if body.OrganizationID != "org-1" || body.ClientIP != "203.0.113.9" {
			t.Fatalf("body=%+v", body)
		}
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"status":"allowed"}`))
	}))
	defer srv.Close()

	a := gateway.NewHTTPWireAdmitter(srv.URL, "/wire-admit", "tok")
	if err := a.Admit(context.Background(), "org-1", "203.0.113.9:54321", "db"); err != nil {
		t.Fatal(err)
	}
}

func TestHTTPWireAdmitterDenied(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusForbidden)
		_, _ = w.Write([]byte(`{"detail":"blocked"}`))
	}))
	defer srv.Close()

	a := gateway.NewHTTPWireAdmitter(srv.URL, "", "tok")
	err := a.Admit(context.Background(), "org-1", "198.51.100.1", "db")
	if err == nil {
		t.Fatal("expected error")
	}
	if got := err.Error(); got == "" || got == "wire admit rejected (403): " {
		t.Fatalf("unexpected error: %q", got)
	}
}

func TestHostFromTCPAddr(t *testing.T) {
	t.Parallel()
	cases := map[string]string{
		"203.0.113.9:54321": "203.0.113.9",
		"[2001:db8::1]:15433": "2001:db8::1",
		"203.0.113.9":       "203.0.113.9",
	}
	for in, want := range cases {
		if got := gateway.HostFromTCPAddr(in); got != want {
			t.Fatalf("%q -> %q want %q", in, got, want)
		}
	}
}
