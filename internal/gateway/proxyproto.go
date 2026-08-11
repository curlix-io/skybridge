package gateway

// PROXY protocol (v1 + v2) support for native-client listeners sitting behind an AWS NLB.
//
// The NLB terminates nothing — it forwards the raw TCP stream — but the socket this process
// accepts is the NLB's own forwarding connection, not the original client's. Without PROXY
// protocol, net.Conn.RemoteAddr() reports the NLB's VPC-internal address, which breaks the
// wire-admit per-org IP allowlist check (it always sees an internal IP, so no allowlist entry can
// ever match). Enabling PROXY protocol v2 on the NLB target group makes it prepend a small header
// with the real client address before the first byte of the actual TCP payload; this file parses
// that header and substitutes it for RemoteAddr() on the wrapped connection.
//
// Implemented by hand (v1 text + v2 binary, TCP4/TCP6 only) rather than pulling in a third-party
// module — see the "pure standard library" note in go.mod.

import (
	"bufio"
	"encoding/binary"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"strconv"
	"strings"
	"time"
)

var errProxyProtoHeader = errors.New("gateway: invalid PROXY protocol header")

var proxyProtoV2Sig = [12]byte{0x0D, 0x0A, 0x0D, 0x0A, 0x00, 0x0D, 0x0A, 0x51, 0x55, 0x49, 0x54, 0x0A}

// proxyProtoListener wraps a net.Listener whose accepted connections are prefixed with a PROXY
// protocol v1 or v2 header (as AWS NLB sends when proxy_protocol_v2 is enabled on the target
// group). Accept blocks on parsing that header before returning the connection, so callers see a
// net.Conn whose RemoteAddr() is the original client, not the NLB.
type proxyProtoListener struct {
	net.Listener
	headerTimeout time.Duration
	log           *slog.Logger
}

// WrapProxyProtocol returns a listener that expects a PROXY protocol header on every accepted
// connection. Use only on listeners fronted by a load balancer configured to send one. A peer that
// fails the PROXY handshake (bad header, or timeout) only has that one connection dropped —
// Accept() keeps serving subsequent connections rather than surfacing the error to the caller, so
// one bad/slow client can never take down the whole listener loop (which the caller in main.go
// treats as fatal for the process).
func WrapProxyProtocol(ln net.Listener, headerTimeout time.Duration) net.Listener {
	if headerTimeout <= 0 {
		headerTimeout = 5 * time.Second
	}
	return &proxyProtoListener{Listener: ln, headerTimeout: headerTimeout, log: slog.Default()}
}

func (l *proxyProtoListener) Accept() (net.Conn, error) {
	for {
		conn, err := l.Listener.Accept()
		if err != nil {
			return nil, err
		}
		wrapped, err := l.handshake(conn)
		if err != nil {
			l.log.Warn(fmt.Sprintf("dropping connection from %s: proxy protocol handshake: %v", conn.RemoteAddr(), err))
			conn.Close()
			continue
		}
		return wrapped, nil
	}
}

func (l *proxyProtoListener) handshake(conn net.Conn) (net.Conn, error) {
	_ = conn.SetReadDeadline(time.Now().Add(l.headerTimeout))
	br := bufio.NewReader(conn)
	realAddr, err := readProxyProtocolHeader(br)
	if err != nil {
		return nil, err
	}
	_ = conn.SetReadDeadline(time.Time{})
	return &proxyProtoConn{Conn: conn, r: br, remoteAddr: realAddr}, nil
}

// proxyProtoConn overrides RemoteAddr() with the address recovered from the PROXY protocol header
// and reads through the buffered reader so no payload bytes consumed while peeking are lost.
type proxyProtoConn struct {
	net.Conn
	r          *bufio.Reader
	remoteAddr net.Addr
}

func (c *proxyProtoConn) Read(b []byte) (int, error) { return c.r.Read(b) }

func (c *proxyProtoConn) RemoteAddr() net.Addr {
	if c.remoteAddr != nil {
		return c.remoteAddr
	}
	return c.Conn.RemoteAddr()
}

// readProxyProtocolHeader consumes a v1 or v2 PROXY protocol header from br and returns the
// original client address it carries. For v2 LOCAL connections (health checks) there is no client
// address; the caller's own local address is returned instead so such connections are never
// mistaken for a real client.
func readProxyProtocolHeader(br *bufio.Reader) (net.Addr, error) {
	sig, err := br.Peek(12)
	if err == nil && [12]byte(sig[:12]) == proxyProtoV2Sig {
		return readProxyProtocolV2(br)
	}
	return readProxyProtocolV1(br)
}

func readProxyProtocolV1(br *bufio.Reader) (net.Addr, error) {
	line, err := br.ReadString('\n')
	if err != nil {
		return nil, errProxyProtoHeader
	}
	line = strings.TrimRight(line, "\r\n")
	fields := strings.Split(line, " ")
	if len(fields) < 2 || fields[0] != "PROXY" {
		return nil, errProxyProtoHeader
	}
	switch fields[1] {
	case "UNKNOWN":
		return nil, nil
	case "TCP4", "TCP6":
		if len(fields) != 6 {
			return nil, errProxyProtoHeader
		}
		srcIP := fields[2]
		srcPort, err := strconv.Atoi(fields[4])
		if err != nil {
			return nil, errProxyProtoHeader
		}
		ip := net.ParseIP(srcIP)
		if ip == nil {
			return nil, errProxyProtoHeader
		}
		return &net.TCPAddr{IP: ip, Port: srcPort}, nil
	default:
		return nil, errProxyProtoHeader
	}
}

func readProxyProtocolV2(br *bufio.Reader) (net.Addr, error) {
	header := make([]byte, 16)
	if _, err := readFull(br, header); err != nil {
		return nil, errProxyProtoHeader
	}
	verCmd := header[12]
	version := verCmd >> 4
	command := verCmd & 0x0F
	if version != 2 {
		return nil, errProxyProtoHeader
	}
	addrFamily := header[13] >> 4
	length := binary.BigEndian.Uint16(header[14:16])

	rest := make([]byte, length)
	if length > 0 {
		if _, err := readFull(br, rest); err != nil {
			return nil, errProxyProtoHeader
		}
	}
	if command == 0x0 { // LOCAL: health check / no proxied client, not a real client connection.
		return nil, nil
	}
	if command != 0x1 { // only PROXY is meaningful; anything else is malformed for our use.
		return nil, errProxyProtoHeader
	}
	switch addrFamily {
	case 0x1: // AF_INET
		if len(rest) < 12 {
			return nil, errProxyProtoHeader
		}
		ip := net.IPv4(rest[0], rest[1], rest[2], rest[3])
		srcPort := binary.BigEndian.Uint16(rest[8:10])
		return &net.TCPAddr{IP: ip, Port: int(srcPort)}, nil
	case 0x2: // AF_INET6
		if len(rest) < 36 {
			return nil, errProxyProtoHeader
		}
		ip := net.IP(append([]byte{}, rest[0:16]...))
		srcPort := binary.BigEndian.Uint16(rest[32:34])
		return &net.TCPAddr{IP: ip, Port: int(srcPort)}, nil
	default: // AF_UNSPEC / AF_UNIX — no usable client IP for our purposes.
		return nil, nil
	}
}

func readFull(br *bufio.Reader, buf []byte) (int, error) {
	n := 0
	for n < len(buf) {
		k, err := br.Read(buf[n:])
		n += k
		if err != nil {
			return n, err
		}
	}
	return n, nil
}
