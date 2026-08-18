package agent

import (
	"context"
	"testing"
)

func TestEnsureSelfSignedCertGeneratesOnFirstCall(t *testing.T) {
	dir := t.TempDir()
	certPEM, keyPEM, err := ensureSelfSignedCert(context.Background(), dir, "")
	if err != nil {
		t.Fatalf("ensureSelfSignedCert: %v", err)
	}
	if len(certPEM) == 0 || len(keyPEM) == 0 {
		t.Fatal("expected non-empty cert/key PEM")
	}
	if _, err := tlsCertificateFromPEM(certPEM, keyPEM); err != nil {
		t.Fatalf("generated cert/key did not form a valid pair: %v", err)
	}
}

func TestEnsureSelfSignedCertPersistsAcrossCalls(t *testing.T) {
	dir := t.TempDir()
	ctx := context.Background()
	certPEM1, keyPEM1, err := ensureSelfSignedCert(ctx, dir, "")
	if err != nil {
		t.Fatalf("first call: %v", err)
	}
	certPEM2, keyPEM2, err := ensureSelfSignedCert(ctx, dir, "")
	if err != nil {
		t.Fatalf("second call: %v", err)
	}
	if string(certPEM1) != string(certPEM2) || string(keyPEM1) != string(keyPEM2) {
		t.Fatal("expected the second call to recover the same cert/key persisted by the first, not mint a fresh one")
	}
}

func TestTLSCertificateFromPEMRoundTrip(t *testing.T) {
	certPEM, keyPEM, err := generateSelfSignedCertPEM()
	if err != nil {
		t.Fatalf("generateSelfSignedCertPEM: %v", err)
	}
	if _, err := tlsCertificateFromPEM(certPEM, keyPEM); err != nil {
		t.Fatalf("tlsCertificateFromPEM: %v", err)
	}
}
