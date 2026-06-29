package postgres

import (
	"crypto/tls"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
)

// StartUpstreamTLS performs the Postgres client side of upstream SSL negotiation: it sends an
// SSLRequest, reads the single-byte reply, and — when the server answers 'S' — upgrades conn to TLS
// using cfg, returning the encrypted connection. The caller then proceeds with the StartupMessage and
// auth over the returned conn exactly as before (so both the verbatim and credential-injection paths
// work unchanged over TLS).
//
// This is what lets the agent reach managed databases that require encryption and, in particular,
// unblocks rds_iam injection: the RDS IAM auth token is only accepted over a TLS connection.
//
//   - 'S' → handshake with cfg and return the *tls.Conn.
//   - 'N' → the server does not offer SSL: error when required, otherwise return conn (plaintext).
//
// cfg carries the verification posture (ServerName / RootCAs / InsecureSkipVerify), set by the
// caller per upstream host.
func StartUpstreamTLS(conn net.Conn, cfg *tls.Config, required bool) (net.Conn, error) {
	var req [8]byte
	binary.BigEndian.PutUint32(req[0:4], 8)
	binary.BigEndian.PutUint32(req[4:8], sslRequestCode)
	if _, err := conn.Write(req[:]); err != nil {
		return nil, err
	}
	var resp [1]byte
	if _, err := io.ReadFull(conn, resp[:]); err != nil {
		return nil, fmt.Errorf("postgres: reading upstream SSLRequest reply: %w", err)
	}
	switch resp[0] {
	case 'S':
		if cfg == nil {
			cfg = &tls.Config{} //nolint:gosec // caller is expected to set verification posture
		}
		tconn := tls.Client(conn, cfg)
		if err := tconn.Handshake(); err != nil {
			return nil, fmt.Errorf("postgres: upstream TLS handshake failed: %w", err)
		}
		return tconn, nil
	case 'N':
		if required {
			return nil, errors.New("postgres: upstream does not support SSL but upstream TLS is required")
		}
		return conn, nil
	default:
		return nil, fmt.Errorf("postgres: unexpected reply %q to upstream SSLRequest", resp[0])
	}
}
