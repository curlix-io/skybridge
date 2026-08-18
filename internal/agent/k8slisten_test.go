package agent

import (
	"bufio"
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/curlix-io/skybridge/internal/config"
)

// governed-access-parity coverage for RunK8sAPIListener (docs/design/kubernetes-access-broker.md
// §11.1): the agent serves kubectl directly off a standalone listener, no gateway/tunnel hop.

func TestRunK8sAPIListenerMissingClientTLS(t *testing.T) {
	err := RunK8sAPIListener(context.Background(), config.Agent{K8sAPIListenAddr: "127.0.0.1:0"}, slog.New(slog.NewTextHandler(&bytes.Buffer{}, nil)))
	if err == nil {
		t.Fatal("expected an error for missing client TLS cert/key")
	}
	if !bytes.Contains([]byte(err.Error()), []byte("SKYBRIDGE_K8S_CLIENT_TLS_CERT_PEM")) {
		t.Fatalf("expected missing-client-TLS error, got %q", err.Error())
	}
}

func TestRunK8sAPIListenerMissingResolver(t *testing.T) {
	certPEM, keyPEM, err := selfSignedCertPEMForTest(t)
	if err != nil {
		t.Fatal(err)
	}
	cfg := config.Agent{K8sAPIListenAddr: "127.0.0.1:0", K8sClientTLSCertPEM: certPEM, K8sClientTLSKeyPEM: keyPEM}
	runErr := RunK8sAPIListener(context.Background(), cfg, slog.New(slog.NewTextHandler(&bytes.Buffer{}, nil)))
	if runErr == nil || !bytes.Contains([]byte(runErr.Error()), []byte("SKYBRIDGE_K8S_CREDENTIAL_EXCHANGE_URL")) {
		t.Fatalf("expected missing-resolver error, got %v", runErr)
	}
}

func TestRunK8sAPIListenerBadListenAddr(t *testing.T) {
	certPEM, keyPEM, err := selfSignedCertPEMForTest(t)
	if err != nil {
		t.Fatal(err)
	}
	cfg := config.Agent{
		K8sAPIListenAddr:         "not-a-valid-address",
		K8sClientTLSCertPEM:      certPEM,
		K8sClientTLSKeyPEM:       keyPEM,
		K8sCredentialExchangeURL: "http://127.0.0.1:0",
	}
	if err := RunK8sAPIListener(context.Background(), cfg, slog.New(slog.NewTextHandler(&bytes.Buffer{}, nil))); err == nil {
		t.Fatal("expected a listen error for a malformed address")
	}
}

// TestRunK8sAPIListenerEndToEnd drives the full path: a real TLS client connects to the standalone
// listener (as kubectl would, no gateway involved), the listener exchanges the presented session
// token for a real bearer token against a fake control-plane exchange endpoint, then relays the
// request to a fake in-cluster API server and returns its response.
func TestRunK8sAPIListenerEndToEnd(t *testing.T) {
	// TLS, not plain HTTP: the real cluster API server always speaks HTTPS, and k8sapi's
	// negotiateUpstreamTLS unconditionally does a TLS handshake against this address.
	upstream := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if got := r.Header.Get("Authorization"); got != "Bearer cluster-bearer" {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		w.Write([]byte(`{"kind":"PodList","items":[]}`))
	}))
	defer upstream.Close()
	upstreamAddr := upstream.Listener.Addr().String()

	exchange := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var body k8sExchangeRequest
		_ = json.NewDecoder(r.Body).Decode(&body)
		if body.SessionToken != "session-tok" {
			http.Error(w, `{"detail":"bad token"}`, http.StatusForbidden)
			return
		}
		_ = json.NewEncoder(w).Encode(k8sExchangeResponse{
			BearerToken:        "cluster-bearer",
			InsecureSkipVerify: true, // fake upstream's cert isn't the in-cluster CA
		})
	}))
	defer exchange.Close()

	certPEM, keyPEM, err := selfSignedCertPEMForTest(t)
	if err != nil {
		t.Fatal(err)
	}

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	listenAddr := ln.Addr().String()
	ln.Close()

	cfg := config.Agent{
		K8sAPIListenAddr:         listenAddr,
		K8sAPIUpstreamAddr:       upstreamAddr,
		K8sClientTLSCertPEM:      certPEM,
		K8sClientTLSKeyPEM:       keyPEM,
		K8sCredentialExchangeURL: exchange.URL,
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan error, 1)
	go func() { done <- RunK8sAPIListener(ctx, cfg, slog.New(slog.NewTextHandler(&bytes.Buffer{}, nil))) }()

	var conn net.Conn
	for i := 0; i < 50; i++ {
		conn, err = tls.Dial("tcp", listenAddr, &tls.Config{InsecureSkipVerify: true}) //nolint:gosec // test dials our own ephemeral self-signed cert
		if err == nil {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	if err != nil {
		t.Fatalf("dial listener: %v", err)
	}
	defer conn.Close()

	req, _ := http.NewRequest(http.MethodGet, "/api/v1/pods", nil)
	req.Header.Set("Authorization", "Bearer session-tok")
	req.Write(conn)

	resp, err := http.ReadResponse(bufio.NewReader(conn), req)
	if err != nil {
		t.Fatalf("read response: %v", err)
	}
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected 200 from upstream relay, got %d", resp.StatusCode)
	}

	cancel()
	if err := <-done; err != nil {
		t.Fatalf("RunK8sAPIListener returned an error after cancel: %v", err)
	}
}
