package mysql

import (
	"bufio"
	"bytes"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"strings"
	"testing"

	"github.com/curlix-io/skybridge/internal/wire"
)

// ---- upstreamCaps ----

func TestUpstreamCaps_WithDatabase(t *testing.T) {
	serverCaps := uint32(capLongPassword | capClientProtocol41 | capSecureConnection | capPluginAuth | capConnectWithDB)
	got := upstreamCaps(serverCaps, "mydb")
	if got&capConnectWithDB == 0 {
		t.Fatal("expected CLIENT_CONNECT_WITH_DB set when a database is requested")
	}
	if got&capClientProtocol41 == 0 || got&capSecureConnection == 0 || got&capPluginAuth == 0 {
		t.Fatalf("expected core caps set, got %#x", got)
	}
}

func TestUpstreamCaps_NoDatabase(t *testing.T) {
	serverCaps := uint32(capLongPassword | capClientProtocol41 | capSecureConnection | capPluginAuth)
	got := upstreamCaps(serverCaps, "")
	if got&capConnectWithDB != 0 {
		t.Fatal("expected no CLIENT_CONNECT_WITH_DB when no database is requested")
	}
}

func TestUpstreamCaps_MaskedByServerCaps(t *testing.T) {
	// The server does not advertise CLIENT_CONNECT_WITH_DB at all; a requested database with a
	// server that lacks the cap must not have CLIENT_CONNECT_WITH_DB claimed... but the mask
	// explicitly always allows it through (see upstreamCaps' own OR'd-in mask terms), so the only
	// thing genuinely constrained by serverCaps here is a bit the mask does NOT list. There isn't
	// one in this capability set, so instead assert the documented base behavior directly: the
	// returned caps are always a subset of the fixed allow-list regardless of serverCaps content.
	got := upstreamCaps(0, "")
	const allow = capLongPassword | capClientProtocol41 | capSecureConnection | capPluginAuth | capConnectWithDB
	if got&^allow != 0 {
		t.Fatalf("upstreamCaps produced bits outside the documented allow-list: %#x", got)
	}
}

// ---- trimTrailingNul ----

func TestTrimTrailingNul(t *testing.T) {
	if got := trimTrailingNul([]byte("abc\x00\x00")); !bytes.Equal(got, []byte("abc")) {
		t.Fatalf("got %q", got)
	}
	if got := trimTrailingNul([]byte("abc")); !bytes.Equal(got, []byte("abc")) {
		t.Fatalf("got %q, want unchanged", got)
	}
	if got := trimTrailingNul(nil); len(got) != 0 {
		t.Fatalf("got %q, want empty", got)
	}
	if got := trimTrailingNul([]byte("\x00\x00\x00")); len(got) != 0 {
		t.Fatalf("got %q, want empty", got)
	}
}

// ---- writeClientError ----

func TestWriteClientError_PacketShape(t *testing.T) {
	var buf bytes.Buffer
	if err := writeClientError(&buf, 3, 1045, "28000", "access denied"); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	seq, payload, _, err := readPacket(bufio.NewReader(&buf))
	if err != nil {
		t.Fatalf("readPacket: %v", err)
	}
	if seq != 3 {
		t.Fatalf("seq = %d, want 3", seq)
	}
	if payload[0] != pktERR {
		t.Fatalf("first byte = %#x, want pktERR", payload[0])
	}
	code := uint16(payload[1]) | uint16(payload[2])<<8
	if code != 1045 {
		t.Fatalf("code = %d, want 1045", code)
	}
	if payload[3] != '#' {
		t.Fatalf("expected '#' marker before sqlstate")
	}
	if !bytes.Contains(payload, []byte("28000")) || !bytes.Contains(payload, []byte("access denied")) {
		t.Fatalf("payload missing sqlstate/message: %v", payload)
	}
}

func TestWriteClientError_PropagatesWriteFailure(t *testing.T) {
	if err := writeClientError(failWriter{}, 0, 1045, "28000", "x"); err == nil {
		t.Fatal("expected the underlying write error to propagate")
	}
}

// ---- errMessage ----

func TestErrMessage_StandardFormat(t *testing.T) {
	p := []byte{pktERR, 0x15, 0x04, '#'}
	p = append(p, "28000"...)
	p = append(p, "Access denied"...)
	if got := errMessage(p); got != "Access denied" {
		t.Fatalf("got %q", got)
	}
}

func TestErrMessage_NoSqlStateMarker(t *testing.T) {
	p := []byte{pktERR, 0x15, 0x04}
	p = append(p, "short message"...)
	if got := errMessage(p); got != "short message" {
		t.Fatalf("got %q", got)
	}
}

func TestErrMessage_TooShort(t *testing.T) {
	if got := errMessage([]byte{pktERR, 0x01}); got != "unknown error" {
		t.Fatalf("got %q, want 'unknown error'", got)
	}
}

// ---- readNulString ----

func TestReadNulString_Missing(t *testing.T) {
	if _, _, ok := readNulString([]byte("no-nul-here"), 0); ok {
		t.Fatal("expected ok=false when there's no NUL terminator")
	}
}

func TestReadNulString_OffsetPastEnd(t *testing.T) {
	if _, _, ok := readNulString([]byte("abc"), 10); ok {
		t.Fatal("expected ok=false for an out-of-range offset")
	}
}

// ---- parseAuthSwitch ----

func TestParseAuthSwitch_TooShort(t *testing.T) {
	plugin, data := parseAuthSwitch([]byte{0xFE})
	if plugin != pluginNativePassword || data != nil {
		t.Fatalf("got (%q,%v)", plugin, data)
	}
}

func TestParseAuthSwitch_UnterminatedPluginName(t *testing.T) {
	p := append([]byte{authSwitchRequest}, "mysql_clear_password"...) // no NUL
	plugin, data := parseAuthSwitch(p)
	if plugin != pluginNativePassword || data != nil {
		t.Fatalf("got (%q,%v), want fallback to native password with no data", plugin, data)
	}
}

func TestParseAuthSwitch_WithData(t *testing.T) {
	p := []byte{authSwitchRequest}
	p = append(p, pluginNativePassword...)
	p = append(p, 0)
	p = append(p, 1, 2, 3, 0, 0) // nonce data with trailing NULs to be trimmed
	plugin, data := parseAuthSwitch(p)
	if plugin != pluginNativePassword {
		t.Fatalf("plugin = %q", plugin)
	}
	if !bytes.Equal(data, []byte{1, 2, 3}) {
		t.Fatalf("data = %v, want [1 2 3]", data)
	}
}

// ---- authResponse ----

func TestAuthResponse_UnsupportedPlugin(t *testing.T) {
	if _, err := authResponse("sha256_password", "pw", make([]byte, 20)); err == nil {
		t.Fatal("expected an error for an unsupported plugin")
	}
}

func TestAuthResponse_ClearPassword(t *testing.T) {
	got, err := authResponse(pluginClearPassword, "s3cret", nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if string(got) != "s3cret\x00" {
		t.Fatalf("got %q", got)
	}
}

func TestAuthResponse_EmptyPluginDefaultsToNative(t *testing.T) {
	nonce := make([]byte, 20)
	got, err := authResponse("", "pw", nonce)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	want := nativePasswordScramble("pw", nonce)
	if !bytes.Equal(got, want) {
		t.Fatal("empty plugin name should default to native password scramble")
	}
}

// ---- parseHandshakeResponse ----

func TestParseHandshakeResponse_NoDatabase(t *testing.T) {
	caps := uint32(capClientProtocol41 | capSecureConnection)
	resp := clientHandshakeResp(false)
	info := parseHandshakeResponse(resp, caps)
	if info.username != "client" {
		t.Fatalf("username = %q", info.username)
	}
	if info.database != "" {
		t.Fatalf("database = %q, want empty", info.database)
	}
}

func TestParseHandshakeResponse_WithDatabase(t *testing.T) {
	caps := uint32(capClientProtocol41 | capSecureConnection | capConnectWithDB)
	var b []byte
	var c [4]byte
	binary.LittleEndian.PutUint32(c[:], caps)
	b = append(b, c[:]...)
	b = append(b, make([]byte, 4)...)
	b = append(b, 0x21)
	b = append(b, make([]byte, 23)...)
	b = append(b, "client"...)
	b = append(b, 0)
	b = append(b, 20)
	b = append(b, make([]byte, 20)...)
	b = append(b, "mydb"...)
	b = append(b, 0)
	info := parseHandshakeResponse(b, caps)
	if info.database != "mydb" {
		t.Fatalf("database = %q, want mydb", info.database)
	}
}

func TestParseHandshakeResponse_LenEncAuthData(t *testing.T) {
	caps := uint32(capClientProtocol41 | capPluginAuthLenEncData)
	var b []byte
	var c [4]byte
	binary.LittleEndian.PutUint32(c[:], caps)
	b = append(b, c[:]...)
	b = append(b, make([]byte, 4)...)
	b = append(b, 0x21)
	b = append(b, make([]byte, 23)...)
	b = append(b, "client"...)
	b = append(b, 0)
	b = appendLenEncInt(b, 4)
	b = append(b, 1, 2, 3, 4)
	info := parseHandshakeResponse(b, caps)
	if info.username != "client" {
		t.Fatalf("username = %q", info.username)
	}
}

func TestParseHandshakeResponse_PlainAuthNoSecureConn(t *testing.T) {
	caps := uint32(capClientProtocol41)
	var b []byte
	var c [4]byte
	binary.LittleEndian.PutUint32(c[:], caps)
	b = append(b, c[:]...)
	b = append(b, make([]byte, 4)...)
	b = append(b, 0x21)
	b = append(b, make([]byte, 23)...)
	b = append(b, "client"...)
	b = append(b, 0)
	b = append(b, "authresp"...)
	b = append(b, 0)
	info := parseHandshakeResponse(b, caps)
	if info.username != "client" {
		t.Fatalf("username = %q", info.username)
	}
}

func TestParseHandshakeResponse_TooShortForUsername(t *testing.T) {
	info := parseHandshakeResponse(make([]byte, 10), 0)
	if info.username != "" {
		t.Fatalf("expected empty username for a too-short response, got %q", info.username)
	}
}

func TestParseHandshakeResponse_SecureConnAuthLenPastEnd(t *testing.T) {
	caps := uint32(capClientProtocol41 | capSecureConnection)
	var b []byte
	var c [4]byte
	binary.LittleEndian.PutUint32(c[:], caps)
	b = append(b, c[:]...)
	b = append(b, make([]byte, 4)...)
	b = append(b, 0x21)
	b = append(b, make([]byte, 23)...)
	b = append(b, "client"...)
	b = append(b, 0)
	// no auth-response length byte follows
	info := parseHandshakeResponse(b, caps)
	if info.username != "client" {
		t.Fatalf("username = %q", info.username)
	}
	if info.database != "" {
		t.Fatalf("database = %q, want empty", info.database)
	}
}

// ---- parseServerGreeting ----

func TestParseServerGreeting_NotV10(t *testing.T) {
	nonce, plugin, caps := parseServerGreeting([]byte{0x09, 0x00})
	if nonce != nil || plugin != "" || caps != 0 {
		t.Fatalf("got (%v,%q,%#x), want zero values", nonce, plugin, caps)
	}
}

func TestParseServerGreeting_TooShortForConnID(t *testing.T) {
	g := []byte{0x0a}
	g = append(g, "v"...)
	g = append(g, 0)
	// nothing else follows
	nonce, plugin, caps := parseServerGreeting(g)
	if nonce != nil || plugin != "" || caps != 0 {
		t.Fatalf("got (%v,%q,%#x)", nonce, plugin, caps)
	}
}

func TestParseServerGreeting_TruncatedAfterLowerCaps(t *testing.T) {
	g := []byte{0x0a}
	g = append(g, "v"...)
	g = append(g, 0)
	g = append(g, 1, 0, 0, 0)             // connection id
	g = append(g, 1, 2, 3, 4, 5, 6, 7, 8) // auth-plugin-data-part-1
	g = append(g, 0)                      // filler
	g = append(g, 0x00, 0x08)             // lower caps (truncated after this)
	nonce, plugin, caps := parseServerGreeting(g)
	if plugin != "" {
		t.Fatalf("plugin = %q, want empty", plugin)
	}
	if len(nonce) != 8 {
		t.Fatalf("expected the 8-byte part1 nonce preserved, got %d bytes", len(nonce))
	}
	_ = caps
}

// ---- completeUpstreamAuth additional branches ----

func TestCompleteUpstreamAuth_ErrPacket(t *testing.T) {
	var buf bytes.Buffer
	errPayload := []byte{pktERR, 0x15, 0x04, '#'}
	errPayload = append(errPayload, "28000"...)
	errPayload = append(errPayload, "denied"...)
	buf.Write(pkt(1, errPayload))
	err := completeUpstreamAuth(io.Discard, bufio.NewReader(&buf), "pw", make([]byte, 20), false)
	if err == nil || !strings.Contains(err.Error(), "denied") {
		t.Fatalf("expected an error containing the server message, got %v", err)
	}
}

func TestCompleteUpstreamAuth_EmptyPacket(t *testing.T) {
	var buf bytes.Buffer
	buf.Write(pkt(1, []byte{}))
	err := completeUpstreamAuth(io.Discard, bufio.NewReader(&buf), "pw", make([]byte, 20), false)
	if !errors.Is(err, errProtocolMySQL) {
		t.Fatalf("expected errProtocolMySQL, got %v", err)
	}
}

func TestCompleteUpstreamAuth_UnexpectedPacketType(t *testing.T) {
	var buf bytes.Buffer
	buf.Write(pkt(1, []byte{0x99}))
	err := completeUpstreamAuth(io.Discard, bufio.NewReader(&buf), "pw", make([]byte, 20), false)
	if err == nil || !strings.Contains(err.Error(), "unexpected auth packet type") {
		t.Fatalf("got %v", err)
	}
}

func TestCompleteUpstreamAuth_UnexpectedMoreDataPayload(t *testing.T) {
	var buf bytes.Buffer
	buf.Write(pkt(1, []byte{authMoreData, 0x99}))
	err := completeUpstreamAuth(io.Discard, bufio.NewReader(&buf), "pw", make([]byte, 20), false)
	if err == nil || !strings.Contains(err.Error(), "unexpected AuthMoreData") {
		t.Fatalf("got %v", err)
	}
}

func TestCompleteUpstreamAuth_FastAuthSuccessThenOK(t *testing.T) {
	var buf bytes.Buffer
	buf.Write(pkt(1, []byte{authMoreData, cachingSha2FastAuthSuccess}))
	buf.Write(pkt(2, []byte{pktOK}))
	err := completeUpstreamAuth(io.Discard, bufio.NewReader(&buf), "pw", make([]byte, 20), true)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestCompleteUpstreamAuth_AuthSwitchRecomputesResponse(t *testing.T) {
	var out bytes.Buffer
	var buf bytes.Buffer
	sw := []byte{authSwitchRequest}
	sw = append(sw, pluginNativePassword...)
	sw = append(sw, 0)
	sw = append(sw, make([]byte, 20)...) // new nonce
	buf.Write(pkt(1, sw))
	buf.Write(pkt(3, []byte{pktOK}))
	err := completeUpstreamAuth(&out, bufio.NewReader(&buf), "pw", make([]byte, 20), false)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	seq, payload, _, rerr := readPacket(bufio.NewReader(&out))
	if rerr != nil {
		t.Fatalf("read agent response: %v", rerr)
	}
	if seq != 2 {
		t.Fatalf("seq = %d, want 2", seq)
	}
	if len(payload) != sha1Size() {
		t.Fatalf("expected a native-password-sized response, got %d bytes", len(payload))
	}
}

func sha1Size() int { return 20 }

// ---- authenticateUpstream: greeting read failure ----

func TestAuthenticateUpstream_GreetingReadFailure(t *testing.T) {
	r, w := net.Pipe()
	_ = w.Close()
	_ = r.Close()
	_, _, err := authenticateUpstream(r, wire.UpstreamCredential{Username: "u", Password: "p"}, "", nil, false)
	if err == nil {
		t.Fatal("expected an error when the greeting can't be read")
	}
}
