package gateway

import (
	"bufio"
	"bytes"
	"encoding/binary"
	"net"
	"testing"
	"time"
)

func TestWrapProxyProtocol_DefaultsTimeoutWhenNonPositive(t *testing.T) {
	raw, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer raw.Close()
	ln := WrapProxyProtocol(raw, 0).(*proxyProtoListener)
	if ln.headerTimeout != 5*time.Second {
		t.Fatalf("expected default timeout of 5s, got %v", ln.headerTimeout)
	}
}

func TestReadProxyProtocolV1_Unknown(t *testing.T) {
	br := bufio.NewReader(bytes.NewReader([]byte("PROXY UNKNOWN\r\n")))
	addr, err := readProxyProtocolV1(br)
	if err != nil {
		t.Fatal(err)
	}
	if addr != nil {
		t.Fatalf("expected nil addr for UNKNOWN, got %v", addr)
	}
}

func TestReadProxyProtocolV1_BadPrefix(t *testing.T) {
	br := bufio.NewReader(bytes.NewReader([]byte("NOTPROXY foo\r\n")))
	if _, err := readProxyProtocolV1(br); err != errProxyProtoHeader {
		t.Fatalf("want errProxyProtoHeader, got %v", err)
	}
}

func TestReadProxyProtocolV1_WrongFieldCount(t *testing.T) {
	br := bufio.NewReader(bytes.NewReader([]byte("PROXY TCP4 203.0.113.9\r\n")))
	if _, err := readProxyProtocolV1(br); err != errProxyProtoHeader {
		t.Fatalf("want errProxyProtoHeader, got %v", err)
	}
}

func TestReadProxyProtocolV1_BadPort(t *testing.T) {
	br := bufio.NewReader(bytes.NewReader([]byte("PROXY TCP4 203.0.113.9 10.24.0.82 notaport 15432\r\n")))
	if _, err := readProxyProtocolV1(br); err != errProxyProtoHeader {
		t.Fatalf("want errProxyProtoHeader, got %v", err)
	}
}

func TestReadProxyProtocolV1_BadIP(t *testing.T) {
	br := bufio.NewReader(bytes.NewReader([]byte("PROXY TCP4 not-an-ip 10.24.0.82 51234 15432\r\n")))
	if _, err := readProxyProtocolV1(br); err != errProxyProtoHeader {
		t.Fatalf("want errProxyProtoHeader, got %v", err)
	}
}

func TestReadProxyProtocolV1_UnknownFamily(t *testing.T) {
	br := bufio.NewReader(bytes.NewReader([]byte("PROXY TCP5 203.0.113.9 10.24.0.82 51234 15432\r\n")))
	if _, err := readProxyProtocolV1(br); err != errProxyProtoHeader {
		t.Fatalf("want errProxyProtoHeader, got %v", err)
	}
}

func TestReadProxyProtocolV1_NoNewline(t *testing.T) {
	br := bufio.NewReader(bytes.NewReader([]byte("PROXY TCP4 incomplete")))
	if _, err := readProxyProtocolV1(br); err != errProxyProtoHeader {
		t.Fatalf("want errProxyProtoHeader, got %v", err)
	}
}

func buildV2Header(cmd byte, family byte, body []byte) []byte {
	header := append([]byte{}, proxyProtoV2Sig[:]...)
	header = append(header, 0x20|cmd)
	header = append(header, family)
	length := make([]byte, 2)
	binary.BigEndian.PutUint16(length, uint16(len(body)))
	header = append(header, length...)
	header = append(header, body...)
	return header
}

func TestReadProxyProtocolV2_Local(t *testing.T) {
	body := make([]byte, 12)
	raw := buildV2Header(0x0, 0x11, body)
	br := bufio.NewReader(bytes.NewReader(raw))
	addr, err := readProxyProtocolV2(br)
	if err != nil {
		t.Fatal(err)
	}
	if addr != nil {
		t.Fatalf("expected nil addr for LOCAL command, got %v", addr)
	}
}

func TestReadProxyProtocolV2_BadVersion(t *testing.T) {
	raw := append([]byte{}, proxyProtoV2Sig[:]...)
	raw = append(raw, 0x11) // version 1, not 2
	raw = append(raw, 0x11)
	raw = append(raw, 0, 0)
	br := bufio.NewReader(bytes.NewReader(raw))
	if _, err := readProxyProtocolV2(br); err != errProxyProtoHeader {
		t.Fatalf("want errProxyProtoHeader, got %v", err)
	}
}

func TestReadProxyProtocolV2_UnknownCommand(t *testing.T) {
	body := make([]byte, 12)
	raw := buildV2Header(0x2, 0x11, body) // command 2 is neither LOCAL nor PROXY
	br := bufio.NewReader(bytes.NewReader(raw))
	if _, err := readProxyProtocolV2(br); err != errProxyProtoHeader {
		t.Fatalf("want errProxyProtoHeader, got %v", err)
	}
}

func TestReadProxyProtocolV2_TCP4TooShort(t *testing.T) {
	raw := buildV2Header(0x1, 0x11, []byte{1, 2, 3}) // shorter than 12 bytes needed for TCP4
	br := bufio.NewReader(bytes.NewReader(raw))
	if _, err := readProxyProtocolV2(br); err != errProxyProtoHeader {
		t.Fatalf("want errProxyProtoHeader, got %v", err)
	}
}

func TestReadProxyProtocolV2_TCP6(t *testing.T) {
	body := make([]byte, 36)
	srcIP := net.ParseIP("2001:db8::1").To16()
	dstIP := net.ParseIP("2001:db8::2").To16()
	copy(body[0:16], srcIP)
	copy(body[16:32], dstIP)
	binary.BigEndian.PutUint16(body[32:34], 51234)
	binary.BigEndian.PutUint16(body[34:36], 15432)
	raw := buildV2Header(0x1, 0x21, body) // AF_INET6
	br := bufio.NewReader(bytes.NewReader(raw))
	addr, err := readProxyProtocolV2(br)
	if err != nil {
		t.Fatal(err)
	}
	tcp, ok := addr.(*net.TCPAddr)
	if !ok || !tcp.IP.Equal(net.ParseIP("2001:db8::1")) || tcp.Port != 51234 {
		t.Fatalf("unexpected addr: %v", addr)
	}
}

func TestReadProxyProtocolV2_TCP6TooShort(t *testing.T) {
	raw := buildV2Header(0x1, 0x21, make([]byte, 10)) // shorter than 36 bytes needed for TCP6
	br := bufio.NewReader(bytes.NewReader(raw))
	if _, err := readProxyProtocolV2(br); err != errProxyProtoHeader {
		t.Fatalf("want errProxyProtoHeader, got %v", err)
	}
}

func TestReadProxyProtocolV2_UnsupportedFamily(t *testing.T) {
	raw := buildV2Header(0x1, 0x00, nil) // AF_UNSPEC
	br := bufio.NewReader(bytes.NewReader(raw))
	addr, err := readProxyProtocolV2(br)
	if err != nil {
		t.Fatal(err)
	}
	if addr != nil {
		t.Fatalf("expected nil addr for unsupported family, got %v", addr)
	}
}

func TestReadProxyProtocolV2_TruncatedHeader(t *testing.T) {
	br := bufio.NewReader(bytes.NewReader(proxyProtoV2Sig[:8])) // shorter than the fixed 16-byte header
	if _, err := readProxyProtocolV2(br); err != errProxyProtoHeader {
		t.Fatalf("want errProxyProtoHeader, got %v", err)
	}
}

func TestReadProxyProtocolV2_TruncatedBody(t *testing.T) {
	// A well-formed 16-byte header advertising a body longer than what's actually available: the
	// readFull(br, rest) call inside readProxyProtocolV2 must fail before addrFamily is even used.
	header := append([]byte{}, proxyProtoV2Sig[:]...)
	header = append(header, 0x21) // version 2, command PROXY
	header = append(header, 0x11) // AF_INET
	length := make([]byte, 2)
	binary.BigEndian.PutUint16(length, 12) // advertise 12 bytes of body
	header = append(header, length...)
	header = append(header, []byte{1, 2, 3}...) // only 3 actually present
	br := bufio.NewReader(bytes.NewReader(header))
	if _, err := readProxyProtocolV2(br); err != errProxyProtoHeader {
		t.Fatalf("want errProxyProtoHeader, got %v", err)
	}
}

func TestProxyProtoListener_AcceptPropagatesListenerError(t *testing.T) {
	raw, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	ln := WrapProxyProtocol(raw, time.Second)
	raw.Close() // closing the underlying listener makes the next Accept fail immediately
	if _, err := ln.Accept(); err == nil {
		t.Fatal("expected Accept to propagate the underlying listener's error")
	}
}

func TestProxyProtoConn_RemoteAddrFallsBackWhenNil(t *testing.T) {
	client, server := net.Pipe()
	defer client.Close()
	defer server.Close()
	c := &proxyProtoConn{Conn: server, r: bufio.NewReader(server), remoteAddr: nil}
	if c.RemoteAddr() != server.RemoteAddr() {
		t.Fatalf("expected fallback to underlying conn's RemoteAddr when unset")
	}
}
