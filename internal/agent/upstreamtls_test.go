package agent

import (
	"bytes"
	"crypto/tls"
	"crypto/x509"
	"io"
	"log/slog"
	"net"
	"testing"
	"time"

	"github.com/curlix-io/skybridge/internal/config"
	"github.com/curlix-io/skybridge/internal/wire"
	"github.com/curlix-io/skybridge/internal/wire/mysql"
	"github.com/curlix-io/skybridge/internal/wire/postgres"
)

// agentTestTLSConfig builds a server tls.Config from the agent's own self-signed cert helper.
func agentTestTLSConfig(t *testing.T) *tls.Config {
	t.Helper()
	cert, err := generateSelfSignedCert()
	if err != nil {
		t.Fatalf("self-signed cert: %v", err)
	}
	return &tls.Config{Certificates: []tls.Certificate{cert}, MinVersion: tls.VersionTLS12}
}

func TestBuildUpstreamTLSPolicy(t *testing.T) {
	if p, err := buildUpstreamTLSPolicy(config.Agent{}); err != nil || p != nil {
		t.Fatalf("disabled by default: p=%v err=%v", p, err)
	}
	if _, err := buildUpstreamTLSPolicy(config.Agent{UpstreamTLSMode: "bogus"}); err == nil {
		t.Fatal("expected an error for an invalid mode")
	}
	if _, err := buildUpstreamTLSPolicy(config.Agent{
		UpstreamTLSMode:  "verify-full",
		UpstreamTLSCAPEM: []byte("not a pem"),
	}); err == nil {
		t.Fatal("expected an error for an invalid CA bundle")
	}

	p, err := buildUpstreamTLSPolicy(config.Agent{UpstreamTLSMode: "require"})
	if err != nil || !p.enabled() {
		t.Fatalf("require should be enabled: p=%v err=%v", p, err)
	}
	if p.required() != true {
		t.Fatal("require must be a hard requirement")
	}
}

func TestUpstreamTLSPolicyRequired(t *testing.T) {
	cases := map[string]bool{"prefer": false, "require": true, "verify-ca": true, "verify-full": true}
	for mode, want := range cases {
		p := &upstreamTLSPolicy{mode: mode}
		if p.required() != want {
			t.Errorf("mode %q required()=%v want %v", mode, p.required(), want)
		}
	}
}

func TestUpstreamTLSConfigForVerificationPosture(t *testing.T) {
	// prefer/require: encrypt only (skip verification), ServerName derived from host.
	enc := (&upstreamTLSPolicy{mode: "require"}).configFor("db.internal")
	if !enc.InsecureSkipVerify || enc.ServerName != "db.internal" {
		t.Fatalf("require config = %+v", enc)
	}
	// verify-full: verifies chain + hostname (no skip), honoring a ServerName override.
	vf := (&upstreamTLSPolicy{mode: "verify-full", serverName: "rds.example.com"}).configFor("10.0.0.5")
	if vf.InsecureSkipVerify || vf.ServerName != "rds.example.com" {
		t.Fatalf("verify-full config = %+v", vf)
	}
	// verify-ca: skips Go's default verification but installs a chain-only verifier.
	vca := (&upstreamTLSPolicy{mode: "verify-ca"}).configFor("10.0.0.5")
	if !vca.InsecureSkipVerify || vca.VerifyConnection == nil {
		t.Fatalf("verify-ca config = %+v", vca)
	}
}

func TestBuildUpstreamTLSPolicyVerifyCAWithSystemRoots(t *testing.T) {
	// verify-ca with no explicit CA PEM falls back to the system trust pool.
	p, err := buildUpstreamTLSPolicy(config.Agent{UpstreamTLSMode: "verify-ca"})
	if err != nil {
		t.Fatal(err)
	}
	if p == nil || p.mode != "verify-ca" {
		t.Fatalf("expected a verify-ca policy, got %+v", p)
	}
}

func TestBuildUpstreamTLSPolicyWithServerNameOverride(t *testing.T) {
	p, err := buildUpstreamTLSPolicy(config.Agent{UpstreamTLSMode: "require", UpstreamTLSServerName: "custom.example.com"})
	if err != nil {
		t.Fatal(err)
	}
	if p.serverName != "custom.example.com" {
		t.Fatalf("expected serverName override to be captured, got %q", p.serverName)
	}
}

func TestUpstreamTLSConfigForPreferMode(t *testing.T) {
	p := &upstreamTLSPolicy{mode: "prefer"}
	cfg := p.configFor("db.internal")
	if !cfg.InsecureSkipVerify || cfg.ServerName != "db.internal" {
		t.Fatalf("prefer config = %+v", cfg)
	}
}

func TestPolicyStartUpstreamTLSSkipsMySQL(t *testing.T) {
	p := &upstreamTLSPolicy{mode: "require"}
	a, b := net.Pipe()
	defer a.Close()
	defer b.Close()
	// MySQL negotiates TLS inside its handshake (handled on the engine, not as a connection wrap), so
	// the policy returns the conn verbatim and must not send any pre-handshake bytes.
	got, err := p.startUpstreamTLS("mysql", a, "db:3306")
	if err != nil || got != a {
		t.Fatalf("mysql should pass through unchanged: got=%v err=%v", got, err)
	}
}

func TestConfigureEngineMySQL(t *testing.T) {
	p := &upstreamTLSPolicy{mode: "require"}
	out := p.configureEngine(mysql.New(), "mysql", "db.internal:3306")
	if out == nil || out.Name() != "mysql" {
		t.Fatalf("expected a configured mysql engine, got %v", out)
	}
	// Postgres/Mongo are wrapped at the connection level, so configureEngine leaves them as-is.
	pg := postgres.New()
	if got := p.configureEngine(pg, "postgres", "db:5432"); got != wire.Engine(pg) {
		t.Fatal("postgres engine should be returned unchanged by configureEngine")
	}
	// A disabled policy is a no-op.
	disabled := (*upstreamTLSPolicy)(nil)
	me := mysql.New()
	if got := disabled.configureEngine(me, "mysql", "db:3306"); got != wire.Engine(me) {
		t.Fatal("disabled policy must return the engine unchanged")
	}
}

// TestPolicyStartUpstreamTLSMongo drives the Mongo path: TLS is established on connect, so the policy
// upgrades the dialed connection immediately and returns a *tls.Conn.
func TestPolicyStartUpstreamTLSMongo(t *testing.T) {
	p := &upstreamTLSPolicy{mode: "require"}
	agentEnd, upstreamEnd := net.Pipe()
	defer agentEnd.Close()
	defer upstreamEnd.Close()
	_ = agentEnd.SetDeadline(time.Now().Add(3 * time.Second))
	_ = upstreamEnd.SetDeadline(time.Now().Add(3 * time.Second))

	out := make(chan net.Conn, 1)
	errc := make(chan error, 1)
	go func() {
		conn, err := p.startUpstreamTLS("mongodb", agentEnd, "mongo.internal:27017")
		if err != nil {
			errc <- err
			return
		}
		out <- conn
	}()
	srv := tls.Server(upstreamEnd, agentTestTLSConfig(t))
	go func() { _ = srv.Handshake() }()

	select {
	case err := <-errc:
		t.Fatalf("mongo startUpstreamTLS: %v", err)
	case conn := <-out:
		if _, ok := conn.(*tls.Conn); !ok {
			t.Fatalf("expected *tls.Conn for mongo upstream, got %T", conn)
		}
	}
}

// TestPolicyStartUpstreamTLSPostgres drives the policy end-to-end for Postgres: it sends an
// SSLRequest and upgrades the connection when the upstream accepts.
func TestPolicyStartUpstreamTLSPostgres(t *testing.T) {
	p := &upstreamTLSPolicy{mode: "require"}
	agentEnd, upstreamEnd := net.Pipe()
	defer agentEnd.Close()
	defer upstreamEnd.Close()
	_ = agentEnd.SetDeadline(time.Now().Add(3 * time.Second))
	_ = upstreamEnd.SetDeadline(time.Now().Add(3 * time.Second))

	out := make(chan net.Conn, 1)
	errc := make(chan error, 1)
	go func() {
		conn, err := p.startUpstreamTLS("postgres", agentEnd, "db.internal:5432")
		if err != nil {
			errc <- err
			return
		}
		out <- conn
	}()

	hdr := make([]byte, 8)
	if _, err := io.ReadFull(upstreamEnd, hdr); err != nil {
		t.Fatalf("read SSLRequest: %v", err)
	}
	if _, err := upstreamEnd.Write([]byte{'S'}); err != nil {
		t.Fatalf("write 'S': %v", err)
	}
	srv := tls.Server(upstreamEnd, agentTestTLSConfig(t))
	go func() { _ = srv.Handshake() }()

	select {
	case err := <-errc:
		t.Fatalf("startUpstreamTLS: %v", err)
	case conn := <-out:
		if _, ok := conn.(*tls.Conn); !ok {
			t.Fatalf("expected *tls.Conn, got %T", conn)
		}
	}
}

func TestPolicyStartUpstreamTLSDisabledPassesThrough(t *testing.T) {
	var p *upstreamTLSPolicy
	a, b := net.Pipe()
	defer a.Close()
	defer b.Close()
	got, err := p.startUpstreamTLS("postgres", a, "db:5432")
	if err != nil || got != a {
		t.Fatalf("disabled policy should pass through unchanged: got=%v err=%v", got, err)
	}
}

func TestPolicyStartUpstreamTLSUnknownDBTypePassesThrough(t *testing.T) {
	p := &upstreamTLSPolicy{mode: "require"}
	a, b := net.Pipe()
	defer a.Close()
	defer b.Close()
	got, err := p.startUpstreamTLS("oracle", a, "db:1521")
	if err != nil || got != a {
		t.Fatalf("unknown db type should pass through unchanged: got=%v err=%v", got, err)
	}
}

func TestHostOnly(t *testing.T) {
	cases := map[string]string{
		"db.internal:5432": "db.internal",
		"10.0.0.5:3306":    "10.0.0.5",
		"no-port-here":     "no-port-here",
	}
	for addr, want := range cases {
		if got := hostOnly(addr); got != want {
			t.Errorf("hostOnly(%q) = %q, want %q", addr, got, want)
		}
	}
}

func TestIsMySQL(t *testing.T) {
	if !isMySQL("mysql") || !isMySQL(" MySQL ") {
		t.Fatal("expected mysql (any case/whitespace) to match")
	}
	if isMySQL("postgres") || isMySQL("") {
		t.Fatal("expected non-mysql db types not to match")
	}
}

func TestUpstreamTLSPolicyRequiredNilPolicy(t *testing.T) {
	var p *upstreamTLSPolicy
	if p.required() {
		t.Fatal("a nil (disabled) policy must never be a hard requirement")
	}
}

// TestUpstreamTLSConfigForVerifyCAVerifiesChain drives configFor("verify-ca")'s VerifyConnection
// callback directly: it must reject a connection presenting no certificate, and successfully verify
// a self-signed certificate that is itself in the trust pool.
func TestUpstreamTLSConfigForVerifyCAVerifiesChain(t *testing.T) {
	cert, err := generateSelfSignedCert()
	if err != nil {
		t.Fatal(err)
	}
	leaf, err := x509.ParseCertificate(cert.Certificate[0])
	if err != nil {
		t.Fatal(err)
	}
	roots := x509.NewCertPool()
	roots.AddCert(leaf)

	p := &upstreamTLSPolicy{mode: "verify-ca", roots: roots}
	cfg := p.configFor("db.internal")
	if cfg.VerifyConnection == nil {
		t.Fatal("expected a VerifyConnection callback for verify-ca")
	}

	if err := cfg.VerifyConnection(tls.ConnectionState{}); err == nil {
		t.Fatal("expected an error when no peer certificate is presented")
	}
	if err := cfg.VerifyConnection(tls.ConnectionState{PeerCertificates: []*x509.Certificate{leaf}}); err != nil {
		t.Fatalf("expected the self-signed leaf (present in roots) to verify, got %v", err)
	}
}

func TestLogUpstreamTLSModeDefaultsNilLogger(t *testing.T) {
	// A nil logger must fall back to slog.Default() rather than panic.
	p := &upstreamTLSPolicy{mode: "require"}
	logUpstreamTLSMode(p, []string{"postgres"}, nil)
}

func TestLogUpstreamTLSModeNoopWhenDisabled(t *testing.T) {
	var buf bytes.Buffer
	logUpstreamTLSMode(nil, []string{"postgres"}, slog.New(slog.NewTextHandler(&buf, nil)))
	if buf.Len() != 0 {
		t.Fatalf("expected no output when policy is disabled, got %q", buf.String())
	}
}

func TestLogUpstreamTLSModeWarnsOnUnverifiedMode(t *testing.T) {
	var buf bytes.Buffer
	p := &upstreamTLSPolicy{mode: "require"}
	logUpstreamTLSMode(p, []string{"postgres"}, slog.New(slog.NewTextHandler(&buf, nil)))
	if !bytes.Contains(buf.Bytes(), []byte("does NOT authenticate")) {
		t.Fatalf("expected an unverified-mode note, got %q", buf.String())
	}
}

func TestLogUpstreamTLSModeSilentOnVerifiedMode(t *testing.T) {
	var buf bytes.Buffer
	p := &upstreamTLSPolicy{mode: "verify-full"}
	logUpstreamTLSMode(p, []string{"postgres"}, slog.New(slog.NewTextHandler(&buf, nil)))
	if bytes.Contains(buf.Bytes(), []byte("does NOT authenticate")) {
		t.Fatalf("expected no unverified-mode note for verify-full, got %q", buf.String())
	}
}

func TestLogUpstreamTLSModeWarnsOnUnsupportedDBType(t *testing.T) {
	var buf bytes.Buffer
	p := &upstreamTLSPolicy{mode: "require"}
	logUpstreamTLSMode(p, []string{"oracle", "oracle", ""}, slog.New(slog.NewTextHandler(&buf, nil)))
	out := buf.String()
	if !bytes.Contains(buf.Bytes(), []byte(`'oracle'`)) {
		t.Fatalf("expected a warning naming the unsupported db type, got %q", out)
	}
	// The dedup/skip-empty logic should produce exactly one such warning line despite the repeat and
	// the empty string in dbTypes.
	if got := bytes.Count(buf.Bytes(), []byte("does not negotiate upstream TLS yet")); got != 1 {
		t.Fatalf("expected exactly one dedup'd warning, got %d in %q", got, out)
	}
}

func TestLogUpstreamTLSModeSilentForSupportedDBTypes(t *testing.T) {
	var buf bytes.Buffer
	p := &upstreamTLSPolicy{mode: "require"}
	logUpstreamTLSMode(p, []string{"postgres", "mysql", "mongodb", "mongo", "postgresql"}, slog.New(slog.NewTextHandler(&buf, nil)))
	if bytes.Contains(buf.Bytes(), []byte("does not negotiate")) {
		t.Fatalf("expected no unsupported-db-type warning for known engines, got %q", buf.String())
	}
}
