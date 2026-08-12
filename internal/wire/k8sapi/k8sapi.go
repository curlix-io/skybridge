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

		if k8sIsUpgrade(req.Header) {
			_ = writeErrorResponse(tlsClient, req, http.StatusForbidden, "interactive subresource not brokered (exec/attach/port-forward)")
			drainAndClose(req.Body)
			continue
		}

		decision := Classify(req.Method, req.URL.Path)
		if decision.Blocked {
			_ = writeErrorResponse(tlsClient, req, http.StatusForbidden, "command blocked by policy: "+decision.Reason)
			drainAndClose(req.Body)
			continue
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

		if upstreamTLS == nil {
			upstreamTLS, err = negotiateUpstreamTLS(upstream, cred)
			if err != nil {
				_ = writeErrorResponse(tlsClient, req, http.StatusBadGateway, "could not reach cluster API server")
				return err
			}
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
