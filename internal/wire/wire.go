// Package wire holds the native database wire-protocol engines. Each engine terminates a native
// client connection and proxies it to an upstream database, applying the masker to result rows
// before they are returned to the client. The upstream connection is dialed by the agent, so raw
// data never leaves the egress network.
package wire

import (
	"context"
	"fmt"
	"io"
	"net"
	"runtime/debug"

	"github.com/curlix-io/skybridge/internal/mask"
)

// Engine proxies one native client connection to one upstream database connection.
type Engine interface {
	// Name is the db_type this engine speaks (postgres | mysql | mongodb).
	Name() string
	// Proxy runs until either side closes or an unrecoverable protocol error occurs. It must not
	// return until both directions are done; the caller closes the connections.
	Proxy(ctx context.Context, client, upstream net.Conn, masker mask.Masker, recorder Recorder) error
}

// Recorder captures a session replay transcript, a pattern common to access proxies generally, as
// the engine's already-masked traffic passes through it. Implementations buffer in memory and ship
// the transcript to the control plane on session close — see internal/gateway/httpstore.go's
// SessionTranscript. RecordInput receives raw client->server bytes (verbatim, before any protocol
// parsing — replay displays these best-effort/opaque, same as the query the client actually
// sent). RecordOutput receives a rendered, human-readable form of one already-masked result unit
// (a decoded row for postgres/mysql, a coarser per-document summary for mongo — see that engine's
// Proxy for why). Implementations must be safe for concurrent use (input and output run on
// separate goroutines) and must never block the proxy loop on a slow control-plane flush.
type Recorder interface {
	RecordInput(raw []byte)
	RecordOutput(text string)
}

// NoopRecorder discards everything. Default when session replay is disabled.
type NoopRecorder struct{}

// RecordInput implements Recorder.
func (NoopRecorder) RecordInput(_ []byte) {}

// RecordOutput implements Recorder.
func (NoopRecorder) RecordOutput(_ string) {}

// recorderWriter adapts a Recorder to an io.Writer so client->server bytes can be tee'd into it
// with io.TeeReader/io.MultiWriter without changing the verbatim-forwarding copy loops.
type recorderWriter struct{ rec Recorder }

func (w recorderWriter) Write(p []byte) (int, error) {
	w.rec.RecordInput(p)
	return len(p), nil
}

// RecorderInputWriter adapts a Recorder to an io.Writer (see recorderWriter) for engines that tee
// client->server bytes into the recorder via io.TeeReader/io.MultiWriter.
func RecorderInputWriter(rec Recorder) io.Writer { return recorderWriter{rec: rec} }

// UpstreamCredential is a database credential the agent uses to authenticate to the upstream when
// credential injection (handoff) is enabled. Database, when empty, leaves the client's requested
// database unchanged.
type UpstreamCredential struct {
	Username string
	Password string
	Database string
}

// CredentialResolver resolves the upstream credential for one injected native session. startup are
// the client's connection parameters (e.g. "user", "database"); secret is the opaque token the
// client presented to the proxy in place of a database password. Returning an error fails the login
// (the engine reports a clean authentication failure to the client). Resolvers must be safe for
// concurrent use.
type CredentialResolver func(ctx context.Context, startup map[string]string, secret string) (UpstreamCredential, error)

// InjectingEngine is an Engine that also supports credential injection: instead of forwarding the
// client's auth handshake verbatim, it terminates the client auth locally, resolves an upstream
// credential via the resolver, and originates its own upstream auth with it — so the client never
// holds a credential the database would accept directly. Engines that do not implement this fall
// back to the verbatim Proxy path.
type InjectingEngine interface {
	Engine
	ProxyInject(ctx context.Context, client, upstream net.Conn, masker mask.Masker, resolve CredentialResolver, recorder Recorder) error
}

// SafeGo runs fn in a new goroutine and sends its result to errc — the same shape as
// `go func() { errc <- fn() }()`, which is how every engine's two per-connection directions
// (client->upstream, upstream->client) are spawned. The difference: a panic inside fn (a malformed
// or adversarial wire message hitting an unhandled parsing edge case) is recovered here and turned
// into an error sent to errc instead of crashing the whole process — one tenant's bad packet must
// never take down every other tenant's connection sharing this agent. Callers' existing `<-errc`
// drain-and-close pattern handles the resulting error exactly like any other connection-ending
// error (EOF, reset, protocol error).
func SafeGo(errc chan<- error, fn func() error) {
	go func() {
		defer func() {
			if r := recover(); r != nil {
				errc <- fmt.Errorf("wire: recovered from panic: %v\n%s", r, debug.Stack())
			}
		}()
		errc <- fn()
	}()
}

// Passthrough is a transparent bidirectional copy with no inspection or masking. Engines that do
// not yet parse their protocol use this so connectivity works while parsing/masking is built out.
// NOTE: no masking is applied — do not enable a Passthrough engine on a PII connection in prod.
func Passthrough(client, upstream net.Conn) error {
	errc := make(chan error, 2)
	go func() { _, err := io.Copy(upstream, client); errc <- err }()
	go func() { _, err := io.Copy(client, upstream); errc <- err }()
	err := <-errc
	_ = client.Close()
	_ = upstream.Close()
	<-errc
	return err
}
