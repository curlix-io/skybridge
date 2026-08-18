package k8sapi

import (
	"bufio"
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/textproto"
	"strings"

	"github.com/curlix-io/skybridge/internal/wire"
)

// maxBodyBytes bounds how much of a single request/response body this engine will buffer in
// memory at once (recordRequestBody, forwardRequest's Secret-masking read). Generous enough for a
// legitimate large `list`/`get -o json` response — k8s objects are individually capped by etcd
// (~1.5 MiB) but a List response aggregates many — while still bounding the worst case: without
// this, a malicious client or a compromised/MITM'd cluster API server could stream an effectively
// unbounded body and exhaust agent memory, since io.ReadAll has no size ceiling of its own.
const maxBodyBytes = 50 << 20

// UpstreamCredential is the real cluster identity the agent authenticates to the API server with,
// resolved from the client-presented session token. Mirrors wire.UpstreamCredential's shape
// (username/password) for the bearer-token auth model the Kubernetes API uses instead of a login
// handshake.
type UpstreamCredential struct {
	BearerToken        string
	CACertPEM          []byte
	InsecureSkipVerify bool
	// AllowInteractiveExec, when true, permits this session to open exec/attach/port-forward
	// subresources (docs/design/kubernetes-access-broker.md §11.6) — the control plane decides this
	// per session at credential-resolve time (same RBAC decision that already gates every other
	// request), not this engine. Defaults to false (zero value): every existing session that never
	// asked for this stays exactly as blocked as before this field existed.
	AllowInteractiveExec bool
}

// CredentialResolver exchanges a client-presented session token (sent as the request's
// "Authorization: Bearer <token>") for the real cluster credential. Mirrors wire.CredentialResolver
// but resolves per-request rather than once per login handshake — the Kubernetes API has no
// persistent login step, so every request carries its own bearer token.
type CredentialResolver func(ctx context.Context, sessionToken string) (UpstreamCredential, error)

// Engine is the Kubernetes API wire-proxy engine: terminates client HTTPS, swaps the session token
// for the real cluster bearer token, classifies/blocks per policy, and masks Secret payload fields
// in responses before they leave the customer network.
type Engine struct {
	// clientTLS terminates the client's HTTPS connection. Required — unlike Postgres/MySQL where TLS
	// is optional, kubectl always speaks HTTPS to a Kubernetes API server, so there is no plaintext
	// fallback here.
	clientTLS *tls.Config
}

// New returns a Kubernetes API engine that terminates client TLS using cfg.
func New(cfg *tls.Config) *Engine { return &Engine{clientTLS: cfg} }

// Name mirrors wire.Engine.Name for logging, though this engine does not implement wire.Engine (see
// package doc / Proxy below) — the agent dispatches to it as its own explicit case instead of the
// generic proxyConn path.
func (*Engine) Name() string { return "kubernetes" }

// Proxy intentionally does NOT implement wire.Engine/wire.InjectingEngine: Kubernetes auth is a
// bearer token presented fresh on every HTTP request, not a one-time login handshake the way
// wire.CredentialResolver (and every other engine's Proxy/ProxyInject signature) assumes. Call
// ProxyInject below directly from the agent's Kubernetes stream-serving path.
func (e *Engine) ProxyInject(ctx context.Context, client, upstream net.Conn, resolve CredentialResolver, recorder wire.Recorder) error {
	if resolve == nil {
		return errors.New("kubernetes: credential injection requires a resolver")
	}
	if recorder == nil {
		recorder = wire.NoopRecorder{}
	}
	if e.clientTLS == nil {
		return errors.New("kubernetes: client TLS must be configured (kubectl always speaks HTTPS)")
	}

	tlsClient := tls.Server(client, e.clientTLS)
	if err := tlsClient.Handshake(); err != nil {
		return fmt.Errorf("kubernetes: client TLS handshake: %w", err)
	}
	defer tlsClient.Close()

	reader := bufio.NewReaderSize(tlsClient, 1<<16)
	var upstreamTLS *tls.Conn

	for {
		req, err := http.ReadRequest(reader)
		if err != nil {
			if errors.Is(err, io.EOF) {
				return nil
			}
			return err
		}

		if err := recordRequestBody(recorder, req); err != nil {
			return err
		}

		execRequested := isUpgradeSubresource(req.URL.Path) || k8sIsUpgrade(req.Header)

		if !execRequested {
			decision := Classify(req.Method, req.URL.Path)
			if decision.Blocked {
				_ = writeErrorResponse(tlsClient, req, http.StatusForbidden, "command blocked by policy: "+decision.Reason)
				drainAndClose(req.Body)
				continue
			}
		}

		sessionToken := bearerToken(req.Header.Get("Authorization"))
		if sessionToken == "" {
			_ = writeErrorResponse(tlsClient, req, http.StatusUnauthorized, "missing bearer session token")
			drainAndClose(req.Body)
			continue
		}
		cred, err := resolve(ctx, sessionToken)
		if err != nil {
			_ = writeErrorResponse(tlsClient, req, http.StatusForbidden, "session invalid or expired")
			drainAndClose(req.Body)
			continue
		}

		if execRequested && !cred.AllowInteractiveExec {
			_ = writeErrorResponse(tlsClient, req, http.StatusForbidden, "interactive subresource not brokered for this session (exec/attach/port-forward)")
			drainAndClose(req.Body)
			continue
		}

		if upstreamTLS == nil {
			upstreamTLS, err = negotiateUpstreamTLS(upstream, cred)
			if err != nil {
				_ = writeErrorResponse(tlsClient, req, http.StatusBadGateway, "could not reach cluster API server")
				return err
			}
		}

		if execRequested {
			// The exec/attach/port-forward handshake response upgrades this TCP connection into a
			// raw bidirectional multiplexed byte stream (SPDY or the newer WebSocket sub-protocol) —
			// there is no further HTTP request/response to read after this, so relayInteractiveExec
			// owns the connection until either side closes it.
			return relayInteractiveExec(ctx, upstreamTLS, tlsClient, reader, req, cred, recorder)
		}

		if err := forwardRequest(upstreamTLS, tlsClient, req, cred, recorder); err != nil {
			return err
		}
	}
}

func negotiateUpstreamTLS(upstream net.Conn, cred UpstreamCredential) (*tls.Conn, error) {
	tlsCfg := &tls.Config{InsecureSkipVerify: cred.InsecureSkipVerify} //nolint:gosec // explicit per-role opt-in, dev/local clusters only
	if len(cred.CACertPEM) > 0 {
		pool := x509.NewCertPool()
		if pool.AppendCertsFromPEM(cred.CACertPEM) {
			tlsCfg.RootCAs = pool
			tlsCfg.InsecureSkipVerify = false
			// tls.Client requires either ServerName or InsecureSkipVerify; derive it from the
			// already-dialed connection's remote address since the cluster API server's hostname/IP
			// is not otherwise available here (CredentialResolver resolves per-request auth, not
			// connection-time identity).
			if host, _, err := net.SplitHostPort(upstream.RemoteAddr().String()); err == nil && host != "" {
				tlsCfg.ServerName = host
			}
		}
	}
	tconn := tls.Client(upstream, tlsCfg)
	if err := tconn.Handshake(); err != nil {
		return nil, fmt.Errorf("kubernetes: upstream TLS handshake: %w", err)
	}
	return tconn, nil
}

// forwardRequest replays req to upstream with the real bearer token substituted, reads the
// response, masks its body, and writes it back to the client.
func forwardRequest(upstream *tls.Conn, client io.Writer, req *http.Request, cred UpstreamCredential, recorder wire.Recorder) error {
	req.Header.Set("Authorization", "Bearer "+cred.BearerToken)
	req.RequestURI = "" // required by http.Request.Write; the URL is used instead
	if req.URL.Scheme == "" {
		req.URL.Scheme = "https"
	}
	if req.URL.Host == "" {
		req.URL.Host = req.Host
	}
	if err := req.Write(upstream); err != nil {
		return fmt.Errorf("kubernetes: forwarding request upstream: %w", err)
	}

	upstreamReader := bufio.NewReaderSize(upstream, 1<<16)
	resp, err := http.ReadResponse(upstreamReader, req)
	if err != nil {
		return fmt.Errorf("kubernetes: reading upstream response: %w", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(io.LimitReader(resp.Body, maxBodyBytes+1))
	if err != nil {
		return fmt.Errorf("kubernetes: reading upstream response body: %w", err)
	}
	if len(body) > maxBodyBytes {
		return fmt.Errorf("kubernetes: upstream response body exceeds %d bytes", maxBodyBytes)
	}
	masked := maskSecretJSON(body)
	resp.Body = io.NopCloser(bytes.NewReader(masked))
	resp.ContentLength = int64(len(masked))
	resp.Header.Set("Content-Length", fmt.Sprintf("%d", len(masked)))
	recorder.RecordOutput(string(masked))

	return resp.Write(client)
}

// relayInteractiveExec handles an exec/attach/port-forward request once the session's resolved
// credential has explicitly permitted it (docs/design/kubernetes-access-broker.md §11.6). Unlike
// forwardRequest, there is no structured response to mask: the moment the upstream answers with a
// successful upgrade, both ends stop speaking HTTP and start exchanging a multiplexed SPDY or
// WebSocket byte stream (stdin/stdout/stderr/resize frames). This function forwards the initiating
// request, relays the upstream's upgrade response line+headers verbatim (deliberately NOT via
// http.Response.Write — that method assumes a body-bearing response and mishandles 101/undefined
// status semantics), then pumps raw bytes bidirectionally until either side closes.
//
// Recording here is intentionally coarse: every byte crossing the wire in each direction is handed
// to recorder as an opaque chunk, labeled by direction only. There is no per-field secret masking
// (there is no field structure once the stream is raw terminal I/O) — this is the same limitation
// RDP session brokering has left open, not a gap specific to this path. Callers that need masked
// transcripts must keep exec disabled for sessions where that matters (AllowInteractiveExec stays
// false by default for exactly this reason).
func relayInteractiveExec(ctx context.Context, upstream *tls.Conn, client io.Writer, clientReader *bufio.Reader, req *http.Request, cred UpstreamCredential, recorder wire.Recorder) error {
	req.Header.Set("Authorization", "Bearer "+cred.BearerToken)
	req.RequestURI = ""
	if req.URL.Scheme == "" {
		req.URL.Scheme = "https"
	}
	if req.URL.Host == "" {
		req.URL.Host = req.Host
	}
	if err := req.Write(upstream); err != nil {
		return fmt.Errorf("kubernetes: forwarding exec request upstream: %w", err)
	}

	upstreamReader := bufio.NewReaderSize(upstream, 1<<16)
	statusLine, headers, err := readRawHTTPHeader(upstreamReader)
	if err != nil {
		return fmt.Errorf("kubernetes: reading exec upgrade response: %w", err)
	}
	if err := writeRawHTTPHeader(client, statusLine, headers); err != nil {
		return fmt.Errorf("kubernetes: writing exec upgrade response: %w", err)
	}
	if !strings.HasPrefix(statusLine, "HTTP/1.1 101") && !strings.HasPrefix(statusLine, "HTTP/1.0 101") {
		// Upstream declined the upgrade (e.g. RBAC denied at the cluster, pod not found) — it already
		// answered with a normal status; nothing further to relay.
		return nil
	}

	errCh := make(chan error, 2)
	go func() {
		_, err := io.Copy(&recordingWriter{w: upstream, record: recorder.RecordInput}, clientReader)
		errCh <- err
	}()
	go func() {
		_, err := io.Copy(&recordingWriter{w: client, recordOut: recorder.RecordOutput}, upstreamReader)
		errCh <- err
	}()

	select {
	case err := <-errCh:
		if err != nil && !errors.Is(err, io.EOF) {
			return fmt.Errorf("kubernetes: exec stream relay: %w", err)
		}
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

// recordingWriter wraps an io.Writer, feeding every chunk written through it to a recorder callback
// before (record, RecordInput-shaped) or after (recordOut, RecordOutput-shaped) forwarding — exactly
// one of the two fields is set per instance.
type recordingWriter struct {
	w         io.Writer
	record    func([]byte)
	recordOut func(string)
}

func (r *recordingWriter) Write(p []byte) (int, error) {
	n, err := r.w.Write(p)
	if n > 0 {
		if r.record != nil {
			r.record(p[:n])
		}
		if r.recordOut != nil {
			r.recordOut(string(p[:n]))
		}
	}
	return n, err
}

// readRawHTTPHeader reads a status line + header block (terminated by a blank line) without
// touching the body/remaining stream — safe for informational/upgrade responses that
// http.ReadResponse does not model cleanly.
func readRawHTTPHeader(r *bufio.Reader) (statusLine string, headerLines []string, err error) {
	tp := textproto.NewReader(r)
	statusLine, err = tp.ReadLine()
	if err != nil {
		return "", nil, err
	}
	for {
		line, err := tp.ReadLine()
		if err != nil {
			return "", nil, err
		}
		if line == "" {
			break
		}
		headerLines = append(headerLines, line)
	}
	return statusLine, headerLines, nil
}

func writeRawHTTPHeader(w io.Writer, statusLine string, headerLines []string) error {
	var buf bytes.Buffer
	buf.WriteString(statusLine)
	buf.WriteString("\r\n")
	for _, line := range headerLines {
		buf.WriteString(line)
		buf.WriteString("\r\n")
	}
	buf.WriteString("\r\n")
	_, err := w.Write(buf.Bytes())
	return err
}

func recordRequestBody(recorder wire.Recorder, req *http.Request) error {
	if req.Body == nil {
		recorder.RecordInput([]byte(req.Method + " " + req.URL.Path))
		return nil
	}
	raw, err := io.ReadAll(io.LimitReader(req.Body, maxBodyBytes+1))
	if err != nil {
		return err
	}
	if len(raw) > maxBodyBytes {
		return fmt.Errorf("kubernetes: request body exceeds %d bytes", maxBodyBytes)
	}
	_ = req.Body.Close()
	req.Body = io.NopCloser(bytes.NewReader(raw))
	req.ContentLength = int64(len(raw))
	recorder.RecordInput([]byte(req.Method + " " + req.URL.Path + " " + string(raw)))
	return nil
}

func drainAndClose(body io.ReadCloser) {
	if body == nil {
		return
	}
	_, _ = io.Copy(io.Discard, io.LimitReader(body, 1<<20))
	_ = body.Close()
}

func writeErrorResponse(w io.Writer, req *http.Request, status int, message string) error {
	body := fmt.Sprintf(`{"kind":"Status","status":"Failure","message":%q,"code":%d}`, message, status)
	resp := &http.Response{
		StatusCode: status,
		ProtoMajor: 1,
		ProtoMinor: 1,
		Header:     http.Header{"Content-Type": []string{"application/json"}},
		Body:       io.NopCloser(strings.NewReader(body)),
		Request:    req,
	}
	resp.ContentLength = int64(len(body))
	return resp.Write(w)
}

func bearerToken(authHeader string) string {
	const prefix = "Bearer "
	if !strings.HasPrefix(authHeader, prefix) {
		return ""
	}
	return strings.TrimSpace(strings.TrimPrefix(authHeader, prefix))
}

func k8sIsUpgrade(h http.Header) bool { return IsUpgradeRequest(h) }
