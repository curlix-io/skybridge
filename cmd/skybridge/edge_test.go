package main

import (
	"bytes"
	"log/slog"
	"strings"
	"testing"

	"github.com/curlix-io/skybridge/internal/config"
)

// TestLogConnectivitySummaryLogsEachActiveChannelsResolvedHost is a regression test for the class
// of bug where a customer deployment silently dials the WRONG gateway host for one of the (up to
// three) independent outbound channels this process can run — the summary log line is what turns
// that into a one-line read instead of a debugging session. See internal/edge/transport's
// certVerificationErrorHint for the companion diagnostic on the failure side.
func TestLogConnectivitySummaryLogsEachActiveChannelsResolvedHost(t *testing.T) {
	cfg := config.Edge{
		GatewayAddr:   "enroll.example.com:7100",
		TenantID:      "org-1",
		EdgeID:        "edge-1",
		ConnectorKey:  "reusable-key",
		CABundle:      []byte("connector-gateway-ca"),
		StudioGateway: "studio.example.com:7200",
		StudioAgentID: "edge-1",
	}
	cfg.WireProxy.Mode = "tunnel"
	cfg.WireProxy.GatewayAddr = "wire.example.com:8010"
	cfg.WireProxy.ConnectorKey = "reusable-key"
	cfg.WireProxy.WireMtlsCABundlePEM = []byte("wire-mtls-ca")

	var buf bytes.Buffer
	logConnectivitySummary(cfg, slog.New(slog.NewTextHandler(&buf, nil)))
	out := buf.String()

	for _, want := range []string{
		"enroll.example.com:7100", // connector-gateway target
		"studio.example.com:7200", // Studio target -- must NOT be confused with the connector's
		"wire.example.com:8010",   // wire-proxy tunnel target -- must NOT be confused with either
	} {
		if !strings.Contains(out, want) {
			t.Fatalf("expected connectivity summary to mention %q, got:\n%s", want, out)
		}
	}
	// Never log actual CA bytes or the bearer credential itself.
	for _, secret := range []string{"connector-gateway-ca", "wire-mtls-ca", "reusable-key"} {
		if strings.Contains(out, secret) {
			t.Fatalf("connectivity summary must never log secret material, found %q in:\n%s", secret, out)
		}
	}
}

func TestLogConnectivitySummarySkipsDisabledChannels(t *testing.T) {
	var buf bytes.Buffer
	logConnectivitySummary(config.Edge{GatewayAddr: "enroll.example.com:7100"}, slog.New(slog.NewTextHandler(&buf, nil)))
	out := buf.String()

	if strings.Contains(out, "query studio call-home") {
		t.Fatalf("expected no Studio summary line when Studio isn't enabled, got:\n%s", out)
	}
	if strings.Contains(out, "wire-proxy tunnel") {
		t.Fatalf("expected no wire-proxy summary line when it isn't enabled, got:\n%s", out)
	}
}

func TestOrNotConfigured(t *testing.T) {
	if got := orNotConfigured(""); got != "(not configured)" {
		t.Fatalf("expected placeholder for empty string, got %q", got)
	}
	if got := orNotConfigured("host:1234"); got != "host:1234" {
		t.Fatalf("expected passthrough for non-empty string, got %q", got)
	}
}
