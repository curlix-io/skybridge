package gateway

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"io"
	"math/big"
	"net"
	"testing"
	"time"
)

// selfSignedCertForTest mirrors internal/agent's identical test helper — kept package-local to
// avoid a cross-package test dependency.
func selfSignedCertForTest(t *testing.T) tls.Certificate {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber:          serial,
		Subject:               pkix.Name{CommonName: "test"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}
}

// TestPeekClientHelloSNIRealHandshake drives a real tls.Dial against a real listener (a genuine
// ClientHello on the wire, not a hand-built byte string) and confirms PeekClientHelloSNI extracts
// the SNI hostname while leaving the byte stream intact for whatever reads after it — the actual
// handshake completes normally through the replay conn, proving nothing was consumed.
func TestPeekClientHelloSNIRealHandshake(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()

	sniCh := make(chan string, 1)
	errCh := make(chan error, 1)
	go func() {
		raw, err := ln.Accept()
		if err != nil {
			errCh <- err
			return
		}
		sni, replay, err := PeekClientHelloSNI(raw, 5*time.Second)
		if err != nil {
			errCh <- err
			return
		}
		sniCh <- sni

		cert := selfSignedCertForTest(t)
		srv := tls.Server(replay, &tls.Config{Certificates: []tls.Certificate{cert}})
		if err := srv.Handshake(); err != nil {
			errCh <- err
			return
		}
		buf := make([]byte, 5)
		if _, err := io.ReadFull(srv, buf); err != nil {
			errCh <- err
			return
		}
		if string(buf) != "hello" {
			errCh <- err
			return
		}
		errCh <- nil
	}()

	conn, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	client := tls.Client(conn, &tls.Config{ServerName: "org-abc-123.wire.example.com", InsecureSkipVerify: true}) //nolint:gosec // test
	if err := client.Handshake(); err != nil {
		t.Fatalf("client handshake: %v", err)
	}
	if _, err := client.Write([]byte("hello")); err != nil {
		t.Fatalf("write: %v", err)
	}

	select {
	case sni := <-sniCh:
		if sni != "org-abc-123.wire.example.com" {
			t.Fatalf("got SNI %q, want org-abc-123.wire.example.com", sni)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("timed out waiting for SNI")
	}
	if err := <-errCh; err != nil {
		t.Fatalf("server-side relay/handshake after peek failed: %v", err)
	}
}

func TestPeekClientHelloSNINonTLSTraffic(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()

	resultCh := make(chan []byte, 1)
	go func() {
		raw, err := ln.Accept()
		if err != nil {
			return
		}
		_, replay, err := PeekClientHelloSNI(raw, 5*time.Second)
		if err != nil {
			return
		}
		buf := make([]byte, 5)
		_, _ = io.ReadFull(replay, buf)
		resultCh <- buf
	}()

	conn, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	if _, err := conn.Write([]byte("PING!")); err != nil {
		t.Fatal(err)
	}

	select {
	case got := <-resultCh:
		if string(got) != "PING!" {
			t.Fatalf("got %q, want PING! — non-TLS bytes must still replay untouched", got)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("timed out")
	}
}

func TestPeekClientHelloSNIEmptyConnection(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()

	doneCh := make(chan struct{})
	go func() {
		raw, err := ln.Accept()
		if err != nil {
			close(doneCh)
			return
		}
		_, _, _ = PeekClientHelloSNI(raw, 200*time.Millisecond)
		close(doneCh)
	}()

	conn, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	conn.Close() // close immediately, no bytes sent — must not hang or panic

	select {
	case <-doneCh:
	case <-time.After(5 * time.Second):
		t.Fatal("PeekClientHelloSNI hung on an immediately-closed connection")
	}
}
