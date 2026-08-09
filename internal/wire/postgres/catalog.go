package postgres

import (
	"bufio"
	"context"
	"encoding/binary"
	"fmt"
	"net"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/curlix-io/skybridge/internal/wire"
)

const msgQuery = 'Q' // frontend: simple Query

// CatalogCredential is a dedicated, read-only Postgres credential the agent uses only for
// pg_class/pg_namespace lookups (table-identity resolution for PathOverlay — see REDACTION.md's
// "Postgres table-identity resolution" design notes). Deliberately distinct from the client's own
// session credential: a credential-injection session's minted credential is scoped to that one
// client and may not be reusable for a side connection the client never requested, and even without
// injection, tying this connection's lifetime to a client session that can end at any time is the
// wrong shape for a cache meant to persist across sessions.
type CatalogCredential struct {
	Host     string
	Port     string
	User     string
	Password string
	SSLMode  string // "", "disable" — TLS for this connection is a later addition; see ParseCatalogDSN
}

// ParseCatalogDSN parses a standard libpq URL (postgres://user:pass@host:port/dbname?sslmode=...)
// into a CatalogCredential. The database name and any query parameters besides sslmode are ignored:
// CatalogResolver dials one connection per client-requested database (see Resolve), not the DSN's
// own database, since the catalog to introspect is whichever database the client's session is using.
func ParseCatalogDSN(dsn string) (CatalogCredential, error) {
	dsn = strings.TrimSpace(dsn)
	if dsn == "" {
		return CatalogCredential{}, fmt.Errorf("postgres: empty catalog DSN")
	}
	u, err := url.Parse(dsn)
	if err != nil {
		return CatalogCredential{}, fmt.Errorf("postgres: invalid catalog DSN: %w", err)
	}
	if u.Scheme != "postgres" && u.Scheme != "postgresql" {
		return CatalogCredential{}, fmt.Errorf("postgres: invalid catalog DSN: expected postgres:// scheme, got %q", u.Scheme)
	}
	host := u.Hostname()
	if host == "" {
		return CatalogCredential{}, fmt.Errorf("postgres: invalid catalog DSN: missing host")
	}
	port := u.Port()
	if port == "" {
		port = "5432"
	}
	user := ""
	pass := ""
	if u.User != nil {
		user = u.User.Username()
		pass, _ = u.User.Password()
	}
	return CatalogCredential{
		Host:     host,
		Port:     port,
		User:     user,
		Password: pass,
		SSLMode:  u.Query().Get("sslmode"),
	}, nil
}

// tableInfo is a resolved (schema, table) pair for a tableOID.
type tableInfo struct {
	schema string
	table  string
}

// catalogConn is one agent-owned connection to a specific upstream database, dedicated to
// pg_class/pg_namespace lookups. Opened lazily on first use and kept for the process lifetime (one
// per database, tracked in CatalogResolver.conns); never used for anything the client requested.
type catalogConn struct {
	mu   sync.Mutex // serializes queries on this connection; the simple-Query protocol is one-at-a-time
	conn net.Conn
	br   *bufio.Reader
}

// CatalogResolver resolves Postgres tableOIDs to (schema, table) names via a dedicated, agent-owned
// connection per database — never the client's own connection (see the package-level design notes
// in REDACTION.md for why). Safe for concurrent use across many client sessions/goroutines: each
// distinct database gets its own catalogConn and cache, guarded by its own mutex, so one client's
// query traffic never blocks resolution for another's.
type CatalogResolver struct {
	cred CatalogCredential

	mu    sync.Mutex
	conns map[string]*catalogConn         // keyed by database name
	cache map[string]map[uint32]tableInfo // keyed by database name, then tableOID
}

// NewCatalogResolver returns a resolver that dials cred's host/port for each database it's asked
// to resolve identity for, lazily and independently.
func NewCatalogResolver(cred CatalogCredential) *CatalogResolver {
	return &CatalogResolver{
		cred:  cred,
		conns: make(map[string]*catalogConn),
		cache: make(map[string]map[uint32]tableInfo),
	}
}

// catalogDialTimeout bounds how long a catalog-connection dial/auth may take before Resolve gives
// up and returns unresolved (never blocks the client's own row stream indefinitely on a slow/
// unreachable catalog connection).
const catalogDialTimeout = 5 * time.Second

// Resolve returns the (schema, table) name for tableOID in database, best-effort: any failure
// (dial, auth, query error, connection reset) returns ok=false rather than an error — callers
// already treat an unresolved identity as "no label available," exactly like an OID that legitimately
// has no backing table (a computed/derived column), so a catalog outage degrades to today's
// behavior (PathOverlay no-op, fallthrough to layer 3) rather than disrupting the client's session.
func (r *CatalogResolver) Resolve(ctx context.Context, database string, tableOID uint32) (schema, table string, ok bool) {
	if tableOID == 0 {
		return "", "", false
	}
	r.mu.Lock()
	if hit, exists := r.cache[database][tableOID]; exists {
		r.mu.Unlock()
		return hit.schema, hit.table, hit.table != ""
	}
	cc, exists := r.conns[database]
	if !exists {
		cc = &catalogConn{}
		r.conns[database] = cc
	}
	r.mu.Unlock()

	info, err := r.query(ctx, cc, database, tableOID)
	if err != nil {
		// Drop the connection on any error so the next lookup redials rather than reusing a
		// connection left in an unknown state (simple-Query errors can desync a naive reader that
		// doesn't drain to the next ReadyForQuery, and a dial/auth failure never produced one at all).
		r.mu.Lock()
		if r.conns[database] == cc {
			delete(r.conns, database)
		}
		r.mu.Unlock()
		return "", "", false
	}

	r.mu.Lock()
	if r.cache[database] == nil {
		r.cache[database] = make(map[uint32]tableInfo)
	}
	r.cache[database][tableOID] = info
	r.mu.Unlock()
	return info.schema, info.table, info.table != ""
}

// query runs the pg_class/pg_namespace lookup for tableOID over cc, dialing and authenticating cc
// first if it isn't already connected. tableOID is a uint32 parsed straight off the wire (never a
// client-supplied string), so it's inlined directly into the simple-Query text with no injection
// surface — see REDACTION.md's design notes for why this avoids needing the extended/parameterized
// query protocol (Parse/Bind/Execute), matching the precedent set by comparable access proxies
// (e.g. hoop.dev's schema-introspection queries, which also build simple-query text directly).
func (r *CatalogResolver) query(ctx context.Context, cc *catalogConn, database string, tableOID uint32) (tableInfo, error) {
	cc.mu.Lock()
	defer cc.mu.Unlock()

	if cc.conn == nil {
		conn, br, err := dialCatalogConn(ctx, r.cred, database)
		if err != nil {
			return tableInfo{}, err
		}
		cc.conn = conn
		cc.br = br
	}

	q := fmt.Sprintf(
		"SELECT relname, relnamespace::regnamespace::text FROM pg_class WHERE oid = %d",
		tableOID,
	)
	info, err := runSimpleQuery(cc.conn, cc.br, q)
	if err != nil {
		_ = cc.conn.Close()
		cc.conn = nil
		cc.br = nil
		return tableInfo{}, err
	}
	return info, nil
}

// dialCatalogConn opens and authenticates a new connection to database using cred, reusing the
// same wire-level auth primitives (writeStartupMessage/authenticateUpstream) the credential-
// injection path already uses to originate upstream auth.
func dialCatalogConn(ctx context.Context, cred CatalogCredential, database string) (net.Conn, *bufio.Reader, error) {
	dialer := &net.Dialer{Timeout: catalogDialTimeout}
	conn, err := dialer.DialContext(ctx, "tcp", net.JoinHostPort(cred.Host, cred.Port))
	if err != nil {
		return nil, nil, fmt.Errorf("postgres: dial catalog connection: %w", err)
	}
	_ = conn.SetDeadline(time.Now().Add(catalogDialTimeout))
	br := bufio.NewReaderSize(conn, 4096)
	upCred := wire.UpstreamCredential{Username: cred.User, Password: cred.Password, Database: database}
	if err := authenticateUpstream(conn, br, upCred, database); err != nil {
		_ = conn.Close()
		return nil, nil, fmt.Errorf("postgres: authenticate catalog connection: %w", err)
	}
	// Drain the post-auth ParameterStatus/BackendKeyData/ReadyForQuery messages before the first
	// query, same as authenticateUpstream's callers expect.
	if err := drainToReady(br); err != nil {
		_ = conn.Close()
		return nil, nil, err
	}
	_ = conn.SetDeadline(time.Time{})
	return conn, br, nil
}

// drainToReady reads and discards backend messages up to and including the first ReadyForQuery
// ('Z'), which authenticateUpstream leaves unread (it returns as soon as AuthenticationOk arrives).
func drainToReady(br *bufio.Reader) error {
	for {
		typ, payload, err := readBackendMessage(br)
		if err != nil {
			return err
		}
		if typ == msgErrorResponse {
			return fmt.Errorf("postgres: catalog connection setup failed: %s", parseErrorResponse(payload))
		}
		if typ == 'Z' {
			return nil
		}
	}
}

// runSimpleQuery sends q as a simple Query message and reads the single-row/single-column reply
// (relname, schema) this package's queries always shape as. On any protocol/error response it
// returns an error; the caller (query) treats that as a reason to drop and redial the connection.
func runSimpleQuery(w net.Conn, br *bufio.Reader, q string) (tableInfo, error) {
	if err := writeFrontend(w, msgQuery, append([]byte(q), 0)); err != nil {
		return tableInfo{}, err
	}
	var info tableInfo
	var cols []string
	for {
		typ, payload, err := readBackendMessage(br)
		if err != nil {
			return tableInfo{}, err
		}
		switch typ {
		case 'T': // RowDescription
			cols = simpleRowDescriptionNames(payload)
		case 'D': // DataRow
			info = parseCatalogDataRow(payload, cols)
		case msgErrorResponse:
			return tableInfo{}, fmt.Errorf("postgres: catalog query failed: %s", parseErrorResponse(payload))
		case 'Z': // ReadyForQuery: end of this query's response
			return info, nil
		}
	}
}

// simpleRowDescriptionNames returns just the column names from a RowDescription payload — the
// catalog query's result shape is fixed and known, so this only needs enough parsing to walk past
// each column's fixed-width trailer, not parseRowDescription's mask.Column construction.
func simpleRowDescriptionNames(p []byte) []string {
	if len(p) < 2 {
		return nil
	}
	n := int(binary.BigEndian.Uint16(p[0:2]))
	off := 2
	names := make([]string, 0, n)
	for i := 0; i < n; i++ {
		end := indexZero(p, off)
		if end < 0 {
			break
		}
		names = append(names, string(p[off:end]))
		off = end + 1
		if off+18 > len(p) { // tableOID(4) colAttr(2) typeOID(4) typeSize(2) typeMod(4) formatCode(2)
			break
		}
		off += 18
	}
	return names
}

// parseCatalogDataRow decodes a DataRow for the fixed "relname, schema" shape query above returns.
func parseCatalogDataRow(p []byte, cols []string) tableInfo {
	if len(p) < 2 {
		return tableInfo{}
	}
	n := int(binary.BigEndian.Uint16(p[0:2]))
	off := 2
	values := make([]string, n)
	for i := 0; i < n; i++ {
		if off+4 > len(p) {
			return tableInfo{}
		}
		flen := int32(binary.BigEndian.Uint32(p[off : off+4]))
		off += 4
		if flen < 0 {
			continue // NULL
		}
		if off+int(flen) > len(p) {
			return tableInfo{}
		}
		values[i] = string(p[off : off+int(flen)])
		off += int(flen)
	}
	var info tableInfo
	for i, name := range cols {
		if i >= len(values) {
			break
		}
		switch name {
		case "relname":
			info.table = values[i]
		case "relnamespace":
			info.schema = values[i]
		}
	}
	return info
}
