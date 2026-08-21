package transport

import (
	"bytes"
	"errors"
	"log/slog"
	"strings"
	"testing"

	"github.com/curlix-io/skybridge/internal/edge"
)

func TestCertVerificationErrorHintDetectsX509Errors(t *testing.T) {
	err := errors.New(`rpc error: code = Unavailable desc = connection error: desc = "transport: authentication handshake failed: tls: failed to verify certificate: x509: certificate signed by unknown authority"`)
	hint := certVerificationErrorHint(err)
	if hint == "" {
		t.Fatal("expected a non-empty hint for an x509 verification error")
	}
	if !strings.Contains(hint, "SKYBRIDGE_EDGE_GATEWAY") || !strings.Contains(hint, "SKYBRIDGE_CA_BUNDLE_PEM") {
		t.Fatalf("expected hint to mention the actionable env vars, got: %s", hint)
	}
}

func TestCertVerificationErrorHintEmptyForOtherErrors(t *testing.T) {
	cases := []error{
		nil,
		errors.New("error reading server preface: EOF"),
		errors.New("connection refused"),
	}
	for _, err := range cases {
		if hint := certVerificationErrorHint(err); hint != "" {
			t.Fatalf("expected empty hint for %v, got: %s", err, hint)
		}
	}
}

func TestLogCertHintOnceLogsOnlyOnce(t *testing.T) {
	var buf bytes.Buffer
	c := New(Config{Target: "127.0.0.1:0"}, edge.NewRegistry(), slog.New(slog.NewTextHandler(&buf, nil)))

	certErr := errors.New("x509: certificate signed by unknown authority")
	c.logCertHintOnce(certErr)
	c.logCertHintOnce(certErr)
	c.logCertHintOnce(certErr)

	out := buf.String()
	count := strings.Count(out, "this looks like a TLS certificate verification failure")
	if count != 1 {
		t.Fatalf("expected the hint to be logged exactly once across repeated failures, got %d occurrences in:\n%s", count, out)
	}
}

func TestLogCertHintOnceNoopForNonCertErrors(t *testing.T) {
	var buf bytes.Buffer
	c := New(Config{Target: "127.0.0.1:0"}, edge.NewRegistry(), slog.New(slog.NewTextHandler(&buf, nil)))

	c.logCertHintOnce(errors.New("error reading server preface: EOF"))

	if buf.Len() != 0 {
		t.Fatalf("expected no log output for a non-cert error, got:\n%s", buf.String())
	}
}
