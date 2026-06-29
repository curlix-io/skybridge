// Credential handoff (design "skybridge-go-wire-proxy" §7 phase 3) for MySQL.
//
// In the default proxy path the agent forwards the client's auth verbatim. Credential *injection*
// flips that: the native client presents an opaque curlix session token instead of a database
// password, the agent terminates that login locally, exchanges the token for a freshly-minted
// upstream credential, and ORIGINATES its own upstream auth with it — so the client never holds a
// credential the database would accept directly.
//
// MySQL's default auth methods (mysql_native_password / caching_sha2_password) are challenge-response,
// so the cleartext token cannot be recovered from them. To recover it the agent therefore:
//
//   - Terminates client TLS (the token is password-equivalent) and presents itself as a MySQL server.
//   - Issues an AuthSwitchRequest to **mysql_clear_password**, which returns the token in cleartext
//     (clients only send it over TLS — connect with the cleartext plugin enabled + TLS).
//
// Upstream it originates a fresh login as the minted user, computing the right response for the
// server's plugin: mysql_native_password (SHA1) or caching_sha2_password (SHA256). caching_sha2
// "full authentication" sends the password in the clear, which MySQL only accepts over a secure
// channel — so it requires upstream TLS (SKYBRIDGE_UPSTREAM_TLS); RSA-key full auth is not supported.
package mysql

import (
	"bufio"
	"context"
	"crypto/rand"
	"crypto/sha1" //nolint:gosec // mysql_native_password is defined in terms of SHA1; not our choice
	"crypto/sha256"
	"crypto/tls"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"strings"

	"github.com/curlix-io/skybridge/internal/mask"
	"github.com/curlix-io/skybridge/internal/wire"
)

const (
	authSwitchRequest = 0xFE
	authMoreData      = 0x01

	cachingSha2FastAuthSuccess = 0x03
	cachingSha2FullAuth        = 0x04

	capLongPassword         = 0x00000001
	capConnectWithDB        = 0x00000008
	capSecureConnection     = 0x00008000
	capPluginAuth           = 0x00080000
	capPluginAuthLenEncData = 0x00200000

	pluginNativePassword = "mysql_native_password"
	pluginCachingSha2    = "caching_sha2_password"
	pluginClearPassword  = "mysql_clear_password"
)

// clientHandshake captures what the agent learned (and the running sequence id) while terminating the
// native client's login, so the command phase and the final OK can be framed correctly.
type clientHandshake struct {
	username string
	database string
	caps     uint32 // client-negotiated capability flags (drives DEPRECATE_EOF in the command phase)
	nextSeq  byte   // sequence id the agent should use for the next packet it sends to the client
}

// ProxyInject implements wire.InjectingEngine for MySQL: it terminates the client login (recovering
// the curlix session token via mysql_clear_password over TLS), resolves an upstream credential, and
// originates the upstream auth itself, then masks result rows exactly as the verbatim path does.
func (e *Engine) ProxyInject(ctx context.Context, client, upstream net.Conn, masker mask.Masker, resolve wire.CredentialResolver) error {
	if masker == nil {
		masker = mask.Noop{}
	}
	if resolve == nil {
		return errors.New("mysql: credential injection requires a resolver")
	}

	client, cb, info, token, err := e.terminateClient(client)
	if err != nil {
		return err
	}

	cred, err := resolve(ctx, map[string]string{"user": info.username, "database": info.database}, token)
	if err != nil {
		_ = writeClientError(client, info.nextSeq, 1045, "28000", "curlix: access denied for this session")
		return err
	}

	db := strings.TrimSpace(cred.Database)
	if db == "" {
		db = info.database
	}
	upstream, sb, err := authenticateUpstream(upstream, cred, db, e.upstreamTLS, e.upstreamRequired)
	if err != nil {
		_ = writeClientError(client, info.nextSeq, 1045, "28000", "curlix: upstream authentication failed")
		return err
	}
	if err := writePacket(client, info.nextSeq, okPayload()); err != nil {
		return err
	}

	// Command phase: identical to the verbatim path, offset 0 (the agent ran both auths itself).
	s := &state{caps: info.caps, queries: make(chan struct{}, 64)}
	errc := make(chan error, 2)
	go func() { errc <- s.clientToServer(cb, upstream) }()
	go func() { errc <- s.serverToClient(ctx, sb, client, masker) }()
	err = <-errc
	_ = client.Close()
	_ = upstream.Close()
	<-errc
	if errors.Is(err, io.EOF) || errors.Is(err, net.ErrClosed) {
		return nil
	}
	return err
}

// terminateClient presents a MySQL server handshake to the native client, optionally terminates its
// TLS, then switches it to mysql_clear_password to recover the presented token. It returns the
// (possibly TLS-wrapped) client conn, a buffered reader positioned for the command phase, the parsed
// handshake, and the cleartext token.
func (e *Engine) terminateClient(client net.Conn) (net.Conn, *bufio.Reader, clientHandshake, string, error) {
	nonce := make([]byte, 20)
	if _, err := rand.Read(nonce); err != nil {
		return nil, nil, clientHandshake{}, "", err
	}
	if err := writePacket(client, 0, e.serverGreeting(nonce)); err != nil {
		return nil, nil, clientHandshake{}, "", err
	}

	cb := bufio.NewReaderSize(client, 1<<16)
	seq, payload, _, err := readPacket(cb)
	if err != nil {
		return nil, nil, clientHandshake{}, "", err
	}
	var caps uint32
	if len(payload) >= 4 {
		caps = binary.LittleEndian.Uint32(payload[:4])
	}
	// SSL request: the client wants TLS before sending its real HandshakeResponse.
	if caps&capClientSSL != 0 {
		if e.clientTLS == nil {
			return nil, nil, clientHandshake{}, "", errors.New("mysql: client requested TLS but no client cert is configured")
		}
		tconn := tls.Server(client, e.clientTLS)
		if err := tconn.Handshake(); err != nil {
			return nil, nil, clientHandshake{}, "", fmt.Errorf("mysql: client TLS handshake failed: %w", err)
		}
		client = tconn
		cb = bufio.NewReaderSize(tconn, 1<<16)
		if seq, payload, _, err = readPacket(cb); err != nil {
			return nil, nil, clientHandshake{}, "", err
		}
		if len(payload) >= 4 {
			caps = binary.LittleEndian.Uint32(payload[:4])
		}
	}

	info := parseHandshakeResponse(payload, caps)

	// Switch the client to cleartext so it hands us the token. (Clients only send it over TLS.)
	switchSeq := seq + 1
	if err := writePacket(client, switchSeq, authSwitchToClear()); err != nil {
		return nil, nil, clientHandshake{}, "", err
	}
	tokSeq, tokPayload, _, err := readPacket(cb)
	if err != nil {
		return nil, nil, clientHandshake{}, "", err
	}
	token := strings.TrimRight(string(tokPayload), "\x00")
	info.nextSeq = tokSeq + 1
	return client, cb, info, token, nil
}

// serverGreeting builds the v10 Initial Handshake the agent sends to the native client. It advertises
// CLIENT_SSL when client TLS is configured so the client encrypts the (token-bearing) handshake.
func (e *Engine) serverGreeting(nonce []byte) []byte {
	capLower := uint16(capLongPassword | capClientProtocol41 | capSecureConnection)
	if e.clientTLS != nil {
		capLower |= capClientSSL
	}
	capUpper := uint16(capPluginAuth >> 16)

	var b []byte
	b = append(b, 0x0a) // protocol version 10
	b = append(b, "8.0.0-curlix"...)
	b = append(b, 0)
	b = append(b, 1, 0, 0, 0) // connection id
	b = append(b, nonce[:8]...)
	b = append(b, 0) // filler
	b = append(b, byte(capLower), byte(capLower>>8))
	b = append(b, 0x21)       // charset utf8_general_ci
	b = append(b, 0x02, 0x00) // status flags: SERVER_STATUS_AUTOCOMMIT
	b = append(b, byte(capUpper), byte(capUpper>>8))
	b = append(b, byte(len(nonce)+1)) // auth-plugin-data length (20 + NUL)
	b = append(b, make([]byte, 10)...)
	b = append(b, nonce[8:20]...) // auth-plugin-data-part-2
	b = append(b, 0)
	b = append(b, pluginNativePassword...)
	b = append(b, 0)
	return b
}

// authSwitchToClear builds an AuthSwitchRequest selecting mysql_clear_password.
func authSwitchToClear() []byte {
	b := []byte{authSwitchRequest}
	b = append(b, pluginClearPassword...)
	b = append(b, 0)
	return b
}

// parseHandshakeResponse extracts the username and database from a PROTOCOL_41 HandshakeResponse.
func parseHandshakeResponse(p []byte, caps uint32) clientHandshake {
	info := clientHandshake{caps: caps}
	off := 32 // caps(4) + max-packet(4) + charset(1) + reserved(23)
	user, off, ok := readNulString(p, off)
	if !ok {
		return info
	}
	info.username = user

	// auth-response (skip): lenenc, or 1-byte-prefixed, or NUL-terminated.
	switch {
	case caps&capPluginAuthLenEncData != 0:
		l, n, ok := readLenEncInt(p, off)
		if !ok {
			return info
		}
		off += n + int(l)
	case caps&capSecureConnection != 0:
		if off >= len(p) {
			return info
		}
		l := int(p[off])
		off += 1 + l
	default:
		_, off, _ = readNulString(p, off)
	}

	if caps&capConnectWithDB != 0 {
		db, _, ok := readNulString(p, off)
		if ok {
			info.database = db
		}
	}
	return info
}

// authenticateUpstream originates a fresh MySQL login against the upstream as cred.Username,
// negotiating upstream TLS when configured and answering the server's auth plugin. It returns the
// (possibly TLS-wrapped) upstream conn and a buffered reader positioned after the auth OK.
func authenticateUpstream(upstream net.Conn, cred wire.UpstreamCredential, database string, upstreamTLS *tls.Config, required bool) (net.Conn, *bufio.Reader, error) {
	sb := bufio.NewReaderSize(upstream, 1<<16)
	_, greeting, _, err := readPacket(sb) // server greeting (seq 0)
	if err != nil {
		return nil, nil, err
	}
	nonce, plugin, serverCaps := parseServerGreeting(greeting)

	seq := byte(0)
	secure := false
	if upstreamTLS != nil {
		if serverCaps&capClientSSL == 0 {
			if required {
				return nil, nil, errors.New("mysql: upstream TLS required but the server does not advertise CLIENT_SSL")
			}
		} else {
			caps := upstreamCaps(serverCaps, database) | capClientSSL
			ssl := make([]byte, sslRequestLen)
			binary.LittleEndian.PutUint32(ssl[0:4], caps)
			binary.LittleEndian.PutUint32(ssl[4:8], maxPacket)
			ssl[8] = 0x21
			if err := writePacket(upstream, seq+1, ssl); err != nil {
				return nil, nil, err
			}
			tconn := tls.Client(upstream, upstreamTLS)
			if err := tconn.Handshake(); err != nil {
				return nil, nil, fmt.Errorf("mysql: upstream TLS handshake failed: %w", err)
			}
			upstream = tconn
			sb = bufio.NewReaderSize(tconn, 1<<16)
			seq++
			secure = true
		}
	}

	if plugin == "" {
		plugin = pluginNativePassword
	}
	resp, err := authResponse(plugin, cred.Password, nonce)
	if err != nil {
		return nil, nil, err
	}
	if err := writePacket(upstream, seq+1, buildHandshakeResponse(cred.Username, database, plugin, resp, secure)); err != nil {
		return nil, nil, err
	}

	if err := completeUpstreamAuth(upstream, sb, cred.Password, nonce, secure); err != nil {
		return nil, nil, err
	}
	return upstream, sb, nil
}

// completeUpstreamAuth drives the post-HandshakeResponse exchange until OK/ERR, handling auth-switch
// (recompute for the requested plugin) and caching_sha2 more-data (fast success, or full auth which
// sends the cleartext password over the secure channel).
func completeUpstreamAuth(upstream io.Writer, sb *bufio.Reader, password string, nonce []byte, secure bool) error {
	for {
		seq, payload, _, err := readPacket(sb)
		if err != nil {
			return err
		}
		if len(payload) == 0 {
			return errProtocolMySQL
		}
		switch payload[0] {
		case pktOK:
			return nil
		case pktERR:
			return fmt.Errorf("mysql: upstream rejected auth: %s", errMessage(payload))
		case authSwitchRequest:
			plugin, switchNonce := parseAuthSwitch(payload)
			if len(switchNonce) > 0 {
				nonce = switchNonce
			}
			resp, err := authResponse(plugin, password, nonce)
			if err != nil {
				return err
			}
			if err := writePacket(upstream, seq+1, resp); err != nil {
				return err
			}
		case authMoreData:
			if len(payload) >= 2 && payload[1] == cachingSha2FastAuthSuccess {
				continue // server will follow with OK
			}
			if len(payload) >= 2 && payload[1] == cachingSha2FullAuth {
				if !secure {
					return errors.New("mysql: caching_sha2_password full authentication requires upstream TLS (set SKYBRIDGE_UPSTREAM_TLS); RSA key exchange is unsupported")
				}
				// Over a secure channel the cleartext password (NUL-terminated) is sent for full auth.
				if err := writePacket(upstream, seq+1, append([]byte(password), 0)); err != nil {
					return err
				}
				continue
			}
			return fmt.Errorf("mysql: unexpected AuthMoreData payload %v", payload)
		default:
			return fmt.Errorf("mysql: unexpected auth packet type 0x%02x", payload[0])
		}
	}
}

var errProtocolMySQL = errors.New("mysql: malformed auth packet")

// upstreamCaps is the capability set the agent advertises to the upstream: PROTOCOL_41 + secure
// connection + plugin auth (+ connect-with-db when a database is requested). DEPRECATE_EOF is left
// off so result sets use classic EOF terminators (matching the command-phase parser).
func upstreamCaps(serverCaps uint32, database string) uint32 {
	caps := uint32(capLongPassword | capClientProtocol41 | capSecureConnection | capPluginAuth)
	if database != "" {
		caps |= capConnectWithDB
	}
	return caps & (serverCaps | capClientProtocol41 | capSecureConnection | capPluginAuth | capConnectWithDB | capLongPassword)
}

// buildHandshakeResponse assembles a PROTOCOL_41 HandshakeResponse for the upstream login.
func buildHandshakeResponse(user, database, plugin string, authResp []byte, secure bool) []byte {
	caps := uint32(capLongPassword | capClientProtocol41 | capSecureConnection | capPluginAuth)
	if database != "" {
		caps |= capConnectWithDB
	}
	if secure {
		caps |= capClientSSL
	}
	var b []byte
	var c [4]byte
	binary.LittleEndian.PutUint32(c[:], caps)
	b = append(b, c[:]...)
	var mp [4]byte
	binary.LittleEndian.PutUint32(mp[:], maxPacket)
	b = append(b, mp[:]...)
	b = append(b, 0x21)                // charset
	b = append(b, make([]byte, 23)...) // reserved
	b = append(b, user...)
	b = append(b, 0)
	b = append(b, byte(len(authResp))) // CLIENT_SECURE_CONNECTION: 1-byte length prefix
	b = append(b, authResp...)
	if database != "" {
		b = append(b, database...)
		b = append(b, 0)
	}
	b = append(b, plugin...)
	b = append(b, 0)
	return b
}

// authResponse computes the auth-response bytes for the named plugin.
func authResponse(plugin, password string, nonce []byte) ([]byte, error) {
	switch plugin {
	case pluginNativePassword, "":
		return nativePasswordScramble(password, nonce), nil
	case pluginCachingSha2:
		return cachingSha2Scramble(password, nonce), nil
	case pluginClearPassword:
		return append([]byte(password), 0), nil
	default:
		return nil, fmt.Errorf("mysql: unsupported upstream auth plugin %q", plugin)
	}
}

// nativePasswordScramble implements mysql_native_password:
// SHA1(password) XOR SHA1(nonce || SHA1(SHA1(password))).
func nativePasswordScramble(password string, nonce []byte) []byte {
	if password == "" {
		return nil
	}
	h1 := sha1.Sum([]byte(password))
	h2 := sha1.Sum(h1[:])
	h := sha1.New()
	h.Write(nonce)
	h.Write(h2[:])
	token := h.Sum(nil)
	out := make([]byte, len(h1))
	for i := range h1 {
		out[i] = h1[i] ^ token[i]
	}
	return out
}

// cachingSha2Scramble implements caching_sha2_password fast-auth:
// SHA256(password) XOR SHA256(SHA256(SHA256(password)) || nonce).
func cachingSha2Scramble(password string, nonce []byte) []byte {
	if password == "" {
		return nil
	}
	d1 := sha256.Sum256([]byte(password))
	d2 := sha256.Sum256(d1[:])
	h := sha256.New()
	h.Write(d2[:])
	h.Write(nonce)
	d3 := h.Sum(nil)
	out := make([]byte, len(d1))
	for i := range d1 {
		out[i] = d1[i] ^ d3[i]
	}
	return out
}

// parseServerGreeting extracts the 20-byte auth nonce, the default auth plugin name and the server's
// capability flags from a v10 Initial Handshake packet.
func parseServerGreeting(g []byte) (nonce []byte, plugin string, caps uint32) {
	if len(g) == 0 || g[0] != 0x0a {
		return nil, "", 0
	}
	off := 1
	for off < len(g) && g[off] != 0 { // server version cstring
		off++
	}
	off++ // NUL
	if off+8+1+2 > len(g) {
		return nil, "", 0
	}
	off += 4 // connection id
	part1 := g[off : off+8]
	off += 8
	off++ // filler
	capLower := binary.LittleEndian.Uint16(g[off : off+2])
	off += 2
	caps = uint32(capLower)
	if off+1+2+2 > len(g) {
		return append([]byte(nil), part1...), "", caps
	}
	off++    // charset
	off += 2 // status flags
	capUpper := binary.LittleEndian.Uint16(g[off : off+2])
	off += 2
	caps |= uint32(capUpper) << 16
	authLen := 0
	if off < len(g) {
		authLen = int(g[off])
	}
	off++
	off += 10 // reserved
	part2Len := 13
	if authLen-8 > part2Len {
		part2Len = authLen - 8
	}
	nonce = make([]byte, 0, 20)
	nonce = append(nonce, part1...)
	if off+12 <= len(g) {
		nonce = append(nonce, g[off:off+12]...) // 12 bytes (drop the trailing NUL of part-2)
	}
	off += part2Len
	if caps&capPluginAuth != 0 {
		if name, _, ok := readNulString(g, off); ok {
			plugin = name
		}
	}
	return nonce, plugin, caps
}

// parseAuthSwitch parses an AuthSwitchRequest into the requested plugin name and its auth data.
func parseAuthSwitch(p []byte) (plugin string, data []byte) {
	if len(p) < 2 {
		return pluginNativePassword, nil
	}
	name, off, ok := readNulString(p, 1)
	if !ok {
		return pluginNativePassword, nil
	}
	if off < len(p) {
		data = append([]byte(nil), p[off:]...)
		data = trimTrailingNul(data)
	}
	return name, data
}

func trimTrailingNul(b []byte) []byte {
	for len(b) > 0 && b[len(b)-1] == 0 {
		b = b[:len(b)-1]
	}
	return b
}

// writeClientError sends an ERR packet to the native client so tools show a clean auth failure.
func writeClientError(w io.Writer, seq byte, code uint16, sqlState, message string) error {
	b := []byte{pktERR, byte(code), byte(code >> 8), '#'}
	b = append(b, sqlState...)
	b = append(b, message...)
	return writePacket(w, seq, b)
}

// okPayload is a minimal PROTOCOL_41 OK packet body (header, affected rows, last insert id, status).
func okPayload() []byte {
	return []byte{pktOK, 0x00, 0x00, 0x02, 0x00, 0x00, 0x00}
}

// errMessage extracts the human-readable text from an ERR packet payload.
func errMessage(p []byte) string {
	// pktERR(1) + code(2) + '#'(1) + sqlstate(5) + message.
	if len(p) >= 9 && p[3] == '#' {
		return string(p[9:])
	}
	if len(p) > 3 {
		return string(p[3:])
	}
	return "unknown error"
}

func readNulString(p []byte, off int) (string, int, bool) {
	for i := off; i < len(p); i++ {
		if p[i] == 0 {
			return string(p[off:i]), i + 1, true
		}
	}
	return "", off, false
}
