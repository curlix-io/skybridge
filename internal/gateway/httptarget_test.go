package gateway_test

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/curlix-io/skybridge/internal/gateway"
)

func TestHTTPTargetResolverResolves(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/wire-targets" {
			t.Fatalf("path=%s", r.URL.Path)
		}
		q := r.URL.Query()
		if q.Get("organization_id") != "org-1" || q.Get("db_type") != "postgres" {
			t.Fatalf("query=%v", q)
		}
		w.WriteHeader(http.StatusOK)
		_ = json.NewEncoder(w).Encode(map[string]any{
			"organization_id": "org-1",
			"targets": []map[string]any{
				{"name": "CurlixPostgresCluster", "addr": "db.internal:5432", "db_type": "POSTGRES", "resource_role_id": "role-1"},
			},
		})
	}))
	defer srv.Close()

	r := gateway.NewHTTPTargetResolver(srv.URL, "/wire-targets", "tok")
	got, err := r.Resolve(context.Background(), "org-1", "postgres")
	if err != nil {
		t.Fatal(err)
	}
	if got.Name != "CurlixPostgresCluster" || got.Addr != "db.internal:5432" || got.DBType != "postgres" || got.ResourceRoleID != "role-1" {
		t.Fatalf("resolved target = %+v", got)
	}
}

func TestHTTPTargetResolverNotFoundStatus(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNotFound)
	}))
	defer srv.Close()

	r := gateway.NewHTTPTargetResolver(srv.URL, "", "tok")
	_, err := r.Resolve(context.Background(), "org-1", "missing")
	if err != gateway.ErrTargetNotFound {
		t.Fatalf("want ErrTargetNotFound, got %v", err)
	}
}

func TestHTTPTargetResolverEmptyListIsNotFound(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		_ = json.NewEncoder(w).Encode(map[string]any{"organization_id": "org-1", "targets": []map[string]any{}})
	}))
	defer srv.Close()

	r := gateway.NewHTTPTargetResolver(srv.URL, "", "tok")
	_, err := r.Resolve(context.Background(), "org-1", "missing")
	if err != gateway.ErrTargetNotFound {
		t.Fatalf("want ErrTargetNotFound, got %v", err)
	}
}

func TestHTTPTargetResolverHTTPError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
		_, _ = w.Write([]byte(`{"detail":"boom"}`))
	}))
	defer srv.Close()

	r := gateway.NewHTTPTargetResolver(srv.URL, "", "tok")
	_, err := r.Resolve(context.Background(), "org-1", "db")
	if err == nil {
		t.Fatal("expected error")
	}
}

func TestHTTPTargetResolverRejectsMissingArgs(t *testing.T) {
	r := gateway.NewHTTPTargetResolver("http://127.0.0.1:0", "", "tok")
	if _, err := r.Resolve(context.Background(), "", "db"); err == nil {
		t.Fatal("expected error for missing organization_id")
	}
	if _, err := r.Resolve(context.Background(), "org-1", ""); err == nil {
		t.Fatal("expected error for missing target")
	}
}

func TestHTTPTargetResolverTransportError(t *testing.T) {
	r := gateway.NewHTTPTargetResolver("http://127.0.0.1:1", "", "tok") // nothing listening
	if _, err := r.Resolve(context.Background(), "org-1", "db"); err == nil {
		t.Fatal("expected a transport-level error")
	}
}

func TestHTTPTargetResolverDecodeError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("not json"))
	}))
	defer srv.Close()

	r := gateway.NewHTTPTargetResolver(srv.URL, "", "tok")
	if _, err := r.Resolve(context.Background(), "org-1", "db"); err == nil {
		t.Fatal("expected a decode error for a malformed response body")
	}
}

func TestNoopTargetResolverFailsClosed(t *testing.T) {
	if _, err := (gateway.NoopTargetResolver{}).Resolve(context.Background(), "org-1", "db"); err != gateway.ErrTargetNotFound {
		t.Fatalf("want ErrTargetNotFound, got %v", err)
	}
}
