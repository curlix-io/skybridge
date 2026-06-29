// Package wire holds the native database wire-protocol engines. Each engine terminates a native
// client connection and proxies it to an upstream database, applying the masker to result rows
// before they are returned to the client. The upstream connection is dialed by the agent, so raw
// data never leaves the egress network.
package wire

import (
	"context"
	"io"
	"net"

	"github.com/curlix-io/skybridge/internal/mask"
)

// Engine proxies one native client connection to one upstream database connection.
type Engine interface {
	// Name is the db_type this engine speaks (postgres | mysql | mongodb).
	Name() string
	// Proxy runs until either side closes or an unrecoverable protocol error occurs. It must not
	// return until both directions are done; the caller closes the connections.
	Proxy(ctx context.Context, client, upstream net.Conn, masker mask.Masker) error
}

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
	ProxyInject(ctx context.Context, client, upstream net.Conn, masker mask.Masker, resolve CredentialResolver) error
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
