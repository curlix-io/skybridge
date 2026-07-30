package gateway_test

import (
	"encoding/binary"
	"net"
	"testing"
	"time"

	"github.com/curlix-io/skybridge/internal/gateway"
)

func acceptOne(t *testing.T, ln net.Listener) (net.Conn, error) {
	t.Helper()
	type result struct {
		conn net.Conn
		err  error
	}
	ch := make(chan result, 1)
	go func() {
		conn, err := ln.Accept()
		ch <- result{conn, err}
	}()
	select {
	case r := <-ch:
		return r.conn, r.err
	case <-time.After(2 * time.Second):
		t.Fatal("Accept timed out")
		return nil, nil
	}
}

func TestWrapProxyProtocolV1RecoversClientIP(t *testing.T) {
	raw, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer raw.Close()
	ln := gateway.WrapProxyProtocol(raw, time.Second)

	client, err := net.Dial("tcp", raw.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	if _, err := client.Write([]byte("PROXY TCP4 203.0.113.9 10.24.0.82 51234 15432\r\n")); err != nil {
		t.Fatal(err)
	}

	server, err := acceptOne(t, ln)
	if err != nil {
		t.Fatal(err)
	}
	defer server.Close()

	got := server.RemoteAddr().(*net.TCPAddr)
	if got.IP.String() != "203.0.113.9" || got.Port != 51234 {
		t.Fatalf("RemoteAddr = %v, want 203.0.113.9:51234", got)
	}
}

func TestWrapProxyProtocolV2RecoversClientIP(t *testing.T) {
	raw, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer raw.Close()
	ln := gateway.WrapProxyProtocol(raw, time.Second)

	client, err := net.Dial("tcp", raw.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	if _, err := client.Write(encodeProxyV2TCP4(net.ParseIP("203.0.113.9"), 51234, net.ParseIP("10.24.0.82"), 15432)); err != nil {
		t.Fatal(err)
	}

	server, err := acceptOne(t, ln)
	if err != nil {
		t.Fatal(err)
	}
	defer server.Close()

	got := server.RemoteAddr().(*net.TCPAddr)
	if got.IP.String() != "203.0.113.9" || got.Port != 51234 {
		t.Fatalf("RemoteAddr = %v, want 203.0.113.9:51234", got)
	}
}

func TestWrapProxyProtocolPayloadSurvivesHeaderParse(t *testing.T) {
	raw, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer raw.Close()
	ln := gateway.WrapProxyProtocol(raw, time.Second)

	client, err := net.Dial("tcp", raw.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	payload := "PROXY TCP4 203.0.113.9 10.24.0.82 51234 15432\r\nhello-payload"
	if _, err := client.Write([]byte(payload)); err != nil {
		t.Fatal(err)
	}

	server, err := acceptOne(t, ln)
	if err != nil {
		t.Fatal(err)
	}
	defer server.Close()

	buf := make([]byte, len("hello-payload"))
	if _, err := server.Read(buf); err != nil {
		t.Fatal(err)
	}
	if string(buf) != "hello-payload" {
		t.Fatalf("payload = %q, want %q", buf, "hello-payload")
	}
}

func TestWrapProxyProtocolMalformedHeaderDropsConnOnly(t *testing.T) {
	raw, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer raw.Close()
	ln := gateway.WrapProxyProtocol(raw, 200*time.Millisecond)

	bad, err := net.Dial("tcp", raw.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := bad.Write([]byte("not a proxy header\r\n")); err != nil {
		t.Fatal(err)
	}
	bad.Close()

	good, err := net.Dial("tcp", raw.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer good.Close()
	if _, err := good.Write([]byte("PROXY TCP4 203.0.113.9 10.24.0.82 51234 15432\r\n")); err != nil {
		t.Fatal(err)
	}

	server, err := acceptOne(t, ln)
	if err != nil {
		t.Fatalf("Accept should skip the malformed connection and return the good one: %v", err)
	}
	defer server.Close()

	got := server.RemoteAddr().(*net.TCPAddr)
	if got.IP.String() != "203.0.113.9" {
		t.Fatalf("RemoteAddr = %v, want 203.0.113.9", got)
	}
}

func encodeProxyV2TCP4(srcIP net.IP, srcPort int, dstIP net.IP, dstPort int) []byte {
	sig := []byte{0x0D, 0x0A, 0x0D, 0x0A, 0x00, 0x0D, 0x0A, 0x51, 0x55, 0x49, 0x54, 0x0A}
	header := append([]byte{}, sig...)
	header = append(header, 0x21) // version 2, command PROXY
	header = append(header, 0x11) // AF_INET, TCP
	body := make([]byte, 12)
	copy(body[0:4], srcIP.To4())
	copy(body[4:8], dstIP.To4())
	binary.BigEndian.PutUint16(body[8:10], uint16(srcPort))
	binary.BigEndian.PutUint16(body[10:12], uint16(dstPort))
	length := make([]byte, 2)
	binary.BigEndian.PutUint16(length, uint16(len(body)))
	header = append(header, length...)
	header = append(header, body...)
	return header
}
