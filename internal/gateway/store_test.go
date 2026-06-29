package gateway_test

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	"github.com/curlix-io/skybridge/internal/gateway"
)

func TestNoopStore(t *testing.T) {
	var s gateway.NoopStore
	id, err := s.SessionStarted(context.Background(), gateway.SessionRecord{})
	if id != "" || err != nil {
		t.Fatalf("noop start = (%q,%v)", id, err)
	}
	if err := s.SessionEnded(context.Background(), "x", gateway.SessionResult{}); err != nil {
		t.Fatalf("noop end = %v", err)
	}
}

func TestHTTPStoreReportsLifecycle(t *testing.T) {
	var (
		mu        sync.Mutex
		startBody gateway.SessionRecord
		endBody   gateway.SessionResult
		closePath string
		authSeen  string
	)

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		defer mu.Unlock()
		authSeen = r.Header.Get("Authorization")
		switch {
		case r.URL.Path == "/api/v1/data-studio/studio/native-sessions" && r.Method == http.MethodPost:
			_ = json.NewDecoder(r.Body).Decode(&startBody)
			w.WriteHeader(http.StatusCreated)
			_, _ = io.WriteString(w, `{"id":"sess-123"}`)
		case r.Method == http.MethodPost && len(r.URL.Path) > len("/api/v1/data-studio/studio/native-sessions/"):
			closePath = r.URL.Path
			_ = json.NewDecoder(r.Body).Decode(&endBody)
			w.WriteHeader(http.StatusOK)
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer srv.Close()

	store := gateway.NewHTTPStore(srv.URL, "", "secret-token")
	id, err := store.SessionStarted(context.Background(), gateway.SessionRecord{
		AgentID: "a1", OrgID: "org1", Target: "db", DBType: "postgres",
		ResourceRoleID: "role-1", ActorEmail: "owner@example.com",
		StartedAt: time.Now().UTC(),
	})
	if err != nil {
		t.Fatal(err)
	}
	if id != "sess-123" {
		t.Fatalf("session id = %q", id)
	}
	if err := store.SessionEnded(context.Background(), id, gateway.SessionResult{
		EndedAt: time.Now().UTC(), BytesUp: 10, BytesDown: 2048, Status: "executed",
	}); err != nil {
		t.Fatal(err)
	}

	mu.Lock()
	defer mu.Unlock()
	if startBody.Target != "db" || startBody.OrgID != "org1" || startBody.DBType != "postgres" {
		t.Fatalf("start body wrong: %+v", startBody)
	}
	if startBody.ResourceRoleID != "role-1" || startBody.ActorEmail != "owner@example.com" {
		t.Fatalf("attribution not serialized: %+v", startBody)
	}
	if closePath != "/api/v1/data-studio/studio/native-sessions/sess-123/close" {
		t.Fatalf("close path = %q", closePath)
	}
	if endBody.BytesDown != 2048 || endBody.Status != "executed" {
		t.Fatalf("end body wrong: %+v", endBody)
	}
	if authSeen != "Bearer secret-token" {
		t.Fatalf("auth header = %q", authSeen)
	}
}

func TestHTTPStoreEndedNoIDSkips(t *testing.T) {
	called := false
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		called = true
	}))
	defer srv.Close()
	store := gateway.NewHTTPStore(srv.URL, "", "")
	if err := store.SessionEnded(context.Background(), "", gateway.SessionResult{}); err != nil {
		t.Fatal(err)
	}
	if called {
		t.Fatal("close with empty id should not hit the control plane")
	}
}

func TestHTTPStoreSurfacesErrorStatus(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "boom", http.StatusInternalServerError)
	}))
	defer srv.Close()
	store := gateway.NewHTTPStore(srv.URL, "", "")
	if _, err := store.SessionStarted(context.Background(), gateway.SessionRecord{}); err == nil {
		t.Fatal("expected error on 500")
	}
}
