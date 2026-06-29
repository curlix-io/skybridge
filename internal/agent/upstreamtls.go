package agent

import (
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"log"
	"net"
	"strings"

	"github.com/curlix-io/skybridge/internal/config"
	"github.com/curlix-io/skybridge/internal/wire"
	"github.com/curlix-io/skybridge/internal/wire/mysql"
	"github.com/curlix-io/skybridge/internal/wire/postgres"
)

// upstreamTLSPolicy captures the agent → database TLS posture. It is built once from config and then
// produces a per-host *tls.Config so the agent can negotiate SSL with the upstream right after dialing
// (and before any startup/auth bytes flow). A nil policy means upstream TLS is disabled.
type upstreamTLSPolicy struct {
	mode       string         // prefer | require | verify-ca | verify-full
	serverName string         // optional SNI / verified-hostname override
	roots      *x509.CertPool // trust roots for verify-* modes (nil for prefer/require)
}

// buildUpstreamTLSPolicy resolves the upstream TLS posture from config. Returns (nil, nil) when
// upstream TLS is disabled, and an error when the mode or trust material is invalid (surfaced at
// startup rather than per-connection).
func buildUpstreamTLSPolicy(cfg config.Agent) (*upstreamTLSPolicy, error) {
	if !cfg.UpstreamTLSEnabled() {
		return nil, nil
	}
	mode := strings.ToLower(strings.TrimSpace(cfg.UpstreamTLSMode))
	switch mode {
	case "prefer", "require", "verify-ca", "verify-full":
	default:
		return nil, fmt.Errorf("SKYBRIDGE_UPSTREAM_TLS=%q is not a valid mode (want disable|prefer|require|verify-ca|verify-full)", cfg.UpstreamTLSMode)
	}

	var roots *x509.CertPool
	if len(cfg.UpstreamTLSCAPEM) > 0 {
		roots = x509.NewCertPool()
		if !roots.AppendCertsFromPEM(cfg.UpstreamTLSCAPEM) {
			return nil, errors.New("SKYBRIDGE_UPSTREAM_TLS_CA_PEM/_FILE contained no valid PEM certificates")
		}
	} else if mode == "verify-ca" || mode == "verify-full" {
		sys, err := x509.SystemCertPool()
		if err != nil {
			return nil, fmt.Errorf("upstream TLS %s: loading system trust roots: %w", mode, err)
		}
		roots = sys
	}

	return &upstreamTLSPolicy{
		mode:       mode,
		serverName: strings.TrimSpace(cfg.UpstreamTLSServerName),
		roots:      roots,
	}, nil
}

// enabled reports whether upstream TLS should be negotiated (nil-safe).
func (p *upstreamTLSPolicy) enabled() bool { return p != nil && p.mode != "" }

// required reports whether a server that declines SSL ('N') is a hard failure. Only "prefer" falls
// back to plaintext.
func (p *upstreamTLSPolicy) required() bool {
	if p == nil {
		return false
	}
	switch p.mode {
	case "require", "verify-ca", "verify-full":
		return true
	default:
		return false
	}
}

// configFor builds the *tls.Config for a specific upstream host. The verification posture follows the
// mode: prefer/require encrypt only; verify-ca authenticates the chain but not the hostname (handy for
// IP-addressed databases); verify-full authenticates chain + hostname.
func (p *upstreamTLSPolicy) configFor(host string) *tls.Config {
	name := p.serverName
	if name == "" {
		name = host
	}
	cfg := &tls.Config{MinVersion: tls.VersionTLS12, ServerName: name}
	switch p.mode {
	case "prefer", "require":
		cfg.InsecureSkipVerify = true //nolint:gosec // encrypt-only mode; verification is opt-in via verify-*
	case "verify-ca":
		// Verify the certificate chain against the configured roots but skip hostname matching, so
		// connections made by IP (common for RDS endpoints reached through private DNS) still verify.
		roots := p.roots
		cfg.InsecureSkipVerify = true //nolint:gosec // chain is verified below via VerifyConnection
		cfg.VerifyConnection = func(cs tls.ConnectionState) error {
			if len(cs.PeerCertificates) == 0 {
				return errors.New("upstream presented no certificate")
			}
			opts := x509.VerifyOptions{Roots: roots, Intermediates: x509.NewCertPool()}
			for _, inter := range cs.PeerCertificates[1:] {
				opts.Intermediates.AddCert(inter)
			}
			_, err := cs.PeerCertificates[0].Verify(opts)
			return err
		}
	case "verify-full":
		cfg.RootCAs = p.roots
	}
	return cfg
}

// startUpstreamTLS upgrades a freshly dialed upstream connection to TLS for the db types whose TLS is
// negotiated *before* the wire protocol begins: Postgres (SSLRequest) and Mongo (TLS on connect). It
// returns the connection unchanged for MySQL — MySQL negotiates TLS inside its seq-numbered handshake,
// so that is handled inside the engine (see configureEngine) — and for any unknown type.
func (p *upstreamTLSPolicy) startUpstreamTLS(dbType string, conn net.Conn, dialAddr string) (net.Conn, error) {
	if !p.enabled() {
		return conn, nil
	}
	host := hostOnly(dialAddr)
	switch {
	case isPostgres(dbType):
		return postgres.StartUpstreamTLS(conn, p.configFor(host), p.required())
	case isMongo(dbType):
		// MongoDB has no in-band STARTTLS: a TLS-enabled server expects the TLS handshake immediately
		// on connect, before any wire bytes. There is nothing to fall back to after a failed handshake
		// on a consumed socket, so "prefer" behaves like "require" for Mongo (documented).
		tconn := tls.Client(conn, p.configFor(host))
		if err := tconn.Handshake(); err != nil {
			return nil, fmt.Errorf("mongo: upstream TLS handshake failed: %w", err)
		}
		return tconn, nil
	default:
		return conn, nil
	}
}

// configureEngine returns the engine to use for one upstream, applying upstream TLS for engines that
// negotiate it inside their own protocol handshake (MySQL). Postgres/Mongo are handled by
// startUpstreamTLS as a connection wrap, so they pass through unchanged here.
func (p *upstreamTLSPolicy) configureEngine(engine wire.Engine, dbType, dialAddr string) wire.Engine {
	if !p.enabled() {
		return engine
	}
	if me, ok := engine.(*mysql.Engine); ok {
		return me.WithUpstreamTLS(p.configFor(hostOnly(dialAddr)), p.required())
	}
	return engine
}

// logUpstreamTLSMode notes the active upstream TLS posture and warns when a weak (unverified) mode is
// in use. Postgres, MySQL and Mongo all negotiate upstream TLS; the db-type list is accepted for
// future engines that may not.
func logUpstreamTLSMode(p *upstreamTLSPolicy, dbTypes []string, logger *log.Logger) {
	if logger == nil {
		logger = log.Default()
	}
	if !p.enabled() {
		return
	}
	logger.Printf("skybridge-agent: upstream TLS ENABLED (mode=%s) for the agent→database hop.", p.mode)
	if p.mode == "prefer" || p.mode == "require" {
		logger.Printf("skybridge-agent: NOTE: upstream TLS mode %q encrypts the agent→database hop but does "+
			"NOT authenticate the server certificate. Use verify-ca/verify-full with "+
			"SKYBRIDGE_UPSTREAM_TLS_CA_FILE to verify the database identity.", p.mode)
	}
	seen := map[string]bool{}
	for _, dt := range dbTypes {
		if dt == "" || seen[dt] || isPostgres(dt) || isMongo(dt) || isMySQL(dt) {
			continue
		}
		seen[dt] = true
		logger.Printf("skybridge-agent: WARNING: upstream TLS is configured but db type %q does not "+
			"negotiate upstream TLS yet; that hop stays plaintext.", dt)
	}
}

func isPostgres(dbType string) bool {
	switch strings.ToLower(strings.TrimSpace(dbType)) {
	case "postgres", "postgresql":
		return true
	default:
		return false
	}
}

func isMongo(dbType string) bool {
	switch strings.ToLower(strings.TrimSpace(dbType)) {
	case "mongodb", "mongo":
		return true
	default:
		return false
	}
}

func isMySQL(dbType string) bool {
	return strings.ToLower(strings.TrimSpace(dbType)) == "mysql"
}

// hostOnly returns the host portion of a host:port dial address, or the input unchanged when it has
// no port.
func hostOnly(addr string) string {
	if host, _, err := net.SplitHostPort(addr); err == nil {
		return host
	}
	return addr
}
