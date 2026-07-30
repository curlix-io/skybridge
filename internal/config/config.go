// Package config loads Skybridge configuration from the environment. All keys are prefixed
// SKYBRIDGE_. The same binary runs as either an egress agent or a relay gateway depending on mode.
package config

import (
	"encoding/json"
	"os"
	"strconv"
	"strings"

	"github.com/curlix-io/skybridge/internal/tunnel"
)

// Mode selects how the agent exposes databases.
const (
	ModeListener = "listener" // agent itself listens for native clients (clients reach the agent)
	ModeTunnel   = "tunnel"   // agent dials the relay gateway and serves streams over an egress tunnel
)

// Agent is the resolved configuration for an egress-side Skybridge agent.
type Agent struct {
	Mode string // listener | tunnel

	// Listener-mode (single target).
	DBType       string // postgres | mysql | mongodb
	ListenAddr   string // local listen address for native clients, e.g. ":15432"
	UpstreamAddr string // upstream database address host:port (dialed by the agent)

	// Tunnel-mode (egress to the gateway, many targets).
	GatewayAddr string // gateway agent endpoint host:port (the agent dials OUT to this)
	AgentID     string // stable agent identity (an org key may be shared by many agents)
	OrgID       string // tenant this agent belongs to; the gateway routes client connections to this
	// agent by org id (one agent process serves one org's databases).
	Token string // shared registration token

	// Targets is the static {name,addr,db_type} list used by LISTENER mode only (SKYBRIDGE_TARGETS).
	// Tunnel mode no longer consults this: the gateway resolves addr/db_type live per connection via
	// a TargetResolver and pushes it on the stream-open payload (see
	// docs/design/skybridge-go-wire-proxy.md §4.2).
	Targets []tunnel.Target

	// Masking (shared by both modes).
	MaskAnalyzeURL   string // empty disables the default remote masker
	MaskAnonymizeURL string
	MaskLanguage     string
	PIIOverlay       map[string]string // column->token overlay you define (off by default)

	// Dynamic overlay source (optional). When PIIOverlayURL is set the agent fetches the org's
	// projected column->token overlay from the control plane at startup and re-fetches on an
	// interval, hot-swapping the overlay rules — so native-client masking follows Administration →
	// PII edits without a redeploy. Falls back to the static PIIOverlay env when the fetch fails.
	PIIOverlayURL         string // GET endpoint, e.g. https://app/api/v1/data-studio/studio/native-access/pii-overlay
	PIIOverlayToken       string // bearer token for the fetch (defaults to SKYBRIDGE_TOKEN)
	PIIOverlayPollSeconds int    // refresh interval in seconds (0 → default 60; <0 → fetch once)

	// Credential handoff / injection (design "skybridge-go-wire-proxy" §7 phase 3). When enabled the
	// agent terminates the native client's login locally (the client presents an opaque curlix
	// session token as its password instead of a database credential), exchanges that token with the
	// control plane for a freshly-minted upstream credential, and originates its own upstream auth.
	// The client therefore never holds a credential the database would accept directly. Disabled by
	// default: the agent forwards the client's auth verbatim, as before.
	InjectCredentials       bool   // SKYBRIDGE_INJECT_CREDENTIALS
	CredentialExchangeURL   string // SKYBRIDGE_CREDENTIAL_EXCHANGE_URL (POST endpoint on the control plane)
	CredentialExchangeToken string // bearer for the exchange call (defaults to SKYBRIDGE_TOKEN)

	// Client-side TLS termination (Postgres). When a cert+key is provided (or a self-signed cert is
	// requested) the agent accepts the native client's SSLRequest and completes a TLS handshake, so
	// the startup handshake and the injected-credential session token travel encrypted instead of in
	// the client's cleartext password. Off by default: SSL is declined and the client link is plaintext.
	ClientTLSCertPEM    []byte // SKYBRIDGE_CLIENT_TLS_CERT_PEM / _FILE
	ClientTLSKeyPEM     []byte // SKYBRIDGE_CLIENT_TLS_KEY_PEM / _FILE
	ClientTLSSelfSigned bool   // SKYBRIDGE_CLIENT_TLS_SELF_SIGNED (dev: generate an ephemeral cert at startup)

	// Upstream (agent → database) TLS (Postgres). When the mode is a TLS mode the agent negotiates
	// SSL with the upstream after dialing (SSLRequest → 'S' → handshake), so the agent→DB hop is
	// encrypted. Required for rds_iam injection (the IAM token is only accepted over TLS). Modes
	// mirror libpq sslmode: disable (default) | prefer | require | verify-ca | verify-full.
	UpstreamTLSMode       string // SKYBRIDGE_UPSTREAM_TLS
	UpstreamTLSCAPEM      []byte // SKYBRIDGE_UPSTREAM_TLS_CA_PEM / _FILE (trust roots for verify-* modes)
	UpstreamTLSServerName string // SKYBRIDGE_UPSTREAM_TLS_SERVER_NAME (override the verified hostname/SNI)

	// Wire-agent mTLS to the gateway tunnel (Phase 2, docs/design/identity-aware-network-access.md).
	// When WireMtlsEnrollURL (or a cached cert under WireMtlsTLSDir) is available, RunTunnel dials
	// the gateway over TLS presenting this agent's client cert instead of the plaintext
	// SKYBRIDGE_TOKEN shared secret. Falls back to bearer-token tunnel mode when unset.
	WireMtlsEnrollURL   string // SKYBRIDGE_WIRE_MTLS_ENROLL_URL (control-plane origin, e.g. https://app.curlix.io)
	WireMtlsEnrollToken string // SKYBRIDGE_WIRE_MTLS_ENROLLMENT_TOKEN (one-time token to bootstrap the first cert)
	WireMtlsTLSDir      string // SKYBRIDGE_WIRE_MTLS_TLS_DIR (persists ca.pem/client.crt/client.key)
	WireMtlsCABundlePEM []byte // SKYBRIDGE_WIRE_MTLS_CA_BUNDLE_PEM / _FILE (pins the enroll call's server TLS)
	WireMtlsTrustDomain string // SKYBRIDGE_WIRE_MTLS_TRUST_DOMAIN (cosmetic; default wiremtls.DefaultTrustDomain)

	// Pre-issued client cert/key (e.g. injected from Secrets Manager), skipping the one-time-token
	// enroll call entirely. Takes priority over WireMtlsEnrollToken/WireMtlsTLSDir — useful on
	// ephemeral compute (Fargate) where there is no persistent disk to cache an enrolled cert
	// across task restarts, and a fresh single-use enroll token can't be minted on every restart.
	WireMtlsClientCertPEM []byte // SKYBRIDGE_WIRE_MTLS_CLIENT_CERT_PEM / _FILE
	WireMtlsClientKeyPEM  []byte // SKYBRIDGE_WIRE_MTLS_CLIENT_KEY_PEM / _FILE

	// AWS-IAM-authenticated enrollment (Vault AWS-auth / aws-iam-authenticator pattern): the agent
	// presigns its own sts:GetCallerIdentity with ambient credentials (e.g. an ECS task role) and
	// exchanges that for an enroll token — no static secret, no human minting a token, safe to call
	// on every renewal/restart. Takes priority over WireMtlsClientCertPEM/WireMtlsEnrollToken when set.
	WireMtlsIamAuthEnabled bool // SKYBRIDGE_WIRE_MTLS_IAM_AUTH (truthy)
}

// ClientTLSConfigured reports whether client-side TLS termination should be enabled.
func (a Agent) ClientTLSConfigured() bool {
	return (len(a.ClientTLSCertPEM) > 0 && len(a.ClientTLSKeyPEM) > 0) || a.ClientTLSSelfSigned
}

// UpstreamTLSEnabled reports whether the agent should negotiate TLS to the upstream database.
func (a Agent) UpstreamTLSEnabled() bool {
	switch strings.ToLower(strings.TrimSpace(a.UpstreamTLSMode)) {
	case "", "disable", "disabled", "off", "false":
		return false
	default:
		return true
	}
}

// LoadAgent reads the agent config from the environment, applying defaults.
func LoadAgent() Agent {
	dbType := strings.ToLower(env("SKYBRIDGE_DB_TYPE", "postgres"))
	a := Agent{
		Mode:                  strings.ToLower(env("SKYBRIDGE_MODE", ModeListener)),
		DBType:                dbType,
		ListenAddr:            env("SKYBRIDGE_LISTEN", defaultListen(dbType)),
		UpstreamAddr:          env("SKYBRIDGE_UPSTREAM", ""),
		GatewayAddr:           env("SKYBRIDGE_GATEWAY", ""),
		AgentID:               env("SKYBRIDGE_AGENT_ID", ""),
		OrgID:                 env("SKYBRIDGE_ORG_ID", ""),
		Token:                 env("SKYBRIDGE_TOKEN", ""),
		Targets:               parseTargets(env("SKYBRIDGE_TARGETS", "")),
		MaskAnalyzeURL:        env("SKYBRIDGE_MASK_ANALYZE_URL", ""),
		MaskAnonymizeURL:      env("SKYBRIDGE_MASK_ANONYMIZE_URL", ""),
		MaskLanguage:          env("SKYBRIDGE_MASK_LANGUAGE", "en"),
		PIIOverlay:            parseOverlay(env("SKYBRIDGE_PII_OVERLAY", "")),
		PIIOverlayURL:         env("SKYBRIDGE_PII_OVERLAY_URL", ""),
		PIIOverlayToken:       env("SKYBRIDGE_PII_OVERLAY_TOKEN", env("SKYBRIDGE_TOKEN", "")),
		PIIOverlayPollSeconds: atoiDefault(env("SKYBRIDGE_PII_OVERLAY_POLL_SECONDS", ""), 60),

		InjectCredentials:       truthy(env("SKYBRIDGE_INJECT_CREDENTIALS", "")),
		CredentialExchangeURL:   env("SKYBRIDGE_CREDENTIAL_EXCHANGE_URL", ""),
		CredentialExchangeToken: env("SKYBRIDGE_CREDENTIAL_EXCHANGE_TOKEN", env("SKYBRIDGE_TOKEN", "")),

		ClientTLSCertPEM:    pemFromEnv("SKYBRIDGE_CLIENT_TLS_CERT_PEM", "SKYBRIDGE_CLIENT_TLS_CERT_FILE"),
		ClientTLSKeyPEM:     pemFromEnv("SKYBRIDGE_CLIENT_TLS_KEY_PEM", "SKYBRIDGE_CLIENT_TLS_KEY_FILE"),
		ClientTLSSelfSigned: truthy(env("SKYBRIDGE_CLIENT_TLS_SELF_SIGNED", "")),

		UpstreamTLSMode:       strings.ToLower(env("SKYBRIDGE_UPSTREAM_TLS", "")),
		UpstreamTLSCAPEM:      pemFromEnv("SKYBRIDGE_UPSTREAM_TLS_CA_PEM", "SKYBRIDGE_UPSTREAM_TLS_CA_FILE"),
		UpstreamTLSServerName: env("SKYBRIDGE_UPSTREAM_TLS_SERVER_NAME", ""),

		WireMtlsEnrollURL:   env("SKYBRIDGE_WIRE_MTLS_ENROLL_URL", ""),
		WireMtlsEnrollToken: env("SKYBRIDGE_WIRE_MTLS_ENROLLMENT_TOKEN", ""),
		WireMtlsTLSDir:      env("SKYBRIDGE_WIRE_MTLS_TLS_DIR", ""),
		WireMtlsCABundlePEM: pemFromEnv("SKYBRIDGE_WIRE_MTLS_CA_BUNDLE_PEM", "SKYBRIDGE_WIRE_MTLS_CA_BUNDLE_FILE"),
		WireMtlsTrustDomain: env("SKYBRIDGE_WIRE_MTLS_TRUST_DOMAIN", ""),

		WireMtlsClientCertPEM: pemFromEnv("SKYBRIDGE_WIRE_MTLS_CLIENT_CERT_PEM", "SKYBRIDGE_WIRE_MTLS_CLIENT_CERT_FILE"),
		WireMtlsClientKeyPEM:  pemFromEnv("SKYBRIDGE_WIRE_MTLS_CLIENT_KEY_PEM", "SKYBRIDGE_WIRE_MTLS_CLIENT_KEY_FILE"),

		WireMtlsIamAuthEnabled: truthy(env("SKYBRIDGE_WIRE_MTLS_IAM_AUTH", "")),
	}
	return a
}

// WireMtlsConfigured reports whether the agent should attempt mTLS for the gateway tunnel instead
// of (or on top of) the legacy bearer token — via IAM auth, a pre-issued cert, or the enroll flow.
func (a Agent) WireMtlsConfigured() bool {
	if a.WireMtlsIamAuthEnabled {
		return true
	}
	if len(a.WireMtlsClientCertPEM) > 0 && len(a.WireMtlsClientKeyPEM) > 0 {
		return true
	}
	return strings.TrimSpace(a.WireMtlsEnrollURL) != ""
}

func atoiDefault(raw string, def int) int {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return def
	}
	n, err := strconv.Atoi(raw)
	if err != nil {
		return def
	}
	return n
}

// TargetByName returns the configured target with the given name.
func (a Agent) TargetByName(name string) (tunnel.Target, bool) {
	for _, t := range a.Targets {
		if t.Name == name {
			return t, true
		}
	}
	return tunnel.Target{}, false
}

// Edge is the resolved configuration for the unified edge binary. The edge runs the egress-only
// call-home transport (dialing OUT to the SaaS Connector Gateway) and, when DB targets are also
// configured, the co-located wire proxy — one process, one identity, for everything that must run
// inside the customer environment.
type Edge struct {
	// Call-home transport (always on when GatewayAddr is set).
	GatewayAddr string // Connector Gateway endpoint host:port (dialed OUT)
	TenantID    string // organization id this edge serves
	EdgeID      string // stable edge instance id
	Token       string // bearer token (when not using mTLS)
	Insecure    bool   // plaintext channel (dev only)

	// mTLS (hardened call-home). When CABundle is set the edge uses mTLS (enrolling if needed);
	// otherwise it falls back to bearer-token-over-TLS using Token.
	CABundle     []byte // CA bundle trusted for the gateway (enables mTLS)
	TLSDir       string // directory holding/persisting ca.pem, client.crt, client.key
	EnrollTarget string // Enroll endpoint host:port (defaults to GatewayAddr)
	EnrollToken  string // one-time enrollment token
	TrustDomain  string // SPIFFE trust domain placed in the CSR SAN (cosmetic)

	// Live read-only AWS access (executed locally at the edge).
	AWSRegion        string
	AWSAssumeRoleARN string
	AWSExternalID    string
	AWSBinary        string

	// Studio execution agent (Query Studio dispatch — curlix.studiogateway.v1 on :7200).
	StudioGateway         string // SKYBRIDGE_STUDIO_GATEWAY host:port
	StudioEnrollGateway   string // SKYBRIDGE_STUDIO_ENROLL_GATEWAY (defaults to StudioGateway)
	StudioEnrollmentToken string
	StudioAgentID         string
	StudioMaxSessions     int
	StudioTargetsJSON     string
	StudioDBUser          string
	StudioDBPassword      string
	StudioTLSDir          string
	StudioTrustDomain     string

	// Optional co-located wire proxy. When non-empty the edge also runs the DB proxy (see Agent).
	WireProxy Agent
}

// LoadEdge reads the unified edge config from the environment.
func LoadEdge() Edge {
	return Edge{
		GatewayAddr:           env("SKYBRIDGE_EDGE_GATEWAY", env("SKYBRIDGE_GATEWAY", "")),
		TenantID:              env("SKYBRIDGE_ORG_ID", ""),
		EdgeID:                env("SKYBRIDGE_EDGE_ID", env("SKYBRIDGE_AGENT_ID", "")),
		Token:                 env("SKYBRIDGE_TOKEN", ""),
		Insecure:              truthy(env("SKYBRIDGE_EDGE_INSECURE", "")),
		CABundle:              pemFromEnv("SKYBRIDGE_CA_BUNDLE_PEM", "SKYBRIDGE_CA_BUNDLE_FILE"),
		TLSDir:                env("SKYBRIDGE_TLS_DIR", ""),
		EnrollTarget:          env("SKYBRIDGE_ENROLL_GATEWAY", ""),
		EnrollToken:           env("SKYBRIDGE_ENROLLMENT_TOKEN", ""),
		TrustDomain:           env("SKYBRIDGE_SPIFFE_TRUST_DOMAIN", ""),
		AWSRegion:             env("SKYBRIDGE_AWS_REGION", ""),
		AWSAssumeRoleARN:      env("SKYBRIDGE_AWS_ASSUME_ROLE_ARN", ""),
		AWSExternalID:         env("SKYBRIDGE_AWS_EXTERNAL_ID", ""),
		AWSBinary:             env("SKYBRIDGE_AWS_BINARY", ""),
		StudioGateway:         env("SKYBRIDGE_STUDIO_GATEWAY", ""),
		StudioEnrollGateway:   env("SKYBRIDGE_STUDIO_ENROLL_GATEWAY", ""),
		StudioEnrollmentToken: env("SKYBRIDGE_STUDIO_ENROLLMENT_TOKEN", ""),
		StudioAgentID:         env("SKYBRIDGE_STUDIO_AGENT_ID", env("SKYBRIDGE_EDGE_ID", "")),
		StudioMaxSessions:     atoiDefault(env("SKYBRIDGE_STUDIO_MAX_SESSIONS", "8"), 8),
		StudioTargetsJSON:     env("SKYBRIDGE_STUDIO_TARGETS", ""),
		StudioDBUser:          env("SKYBRIDGE_STUDIO_DB_USER", ""),
		StudioDBPassword:      env("SKYBRIDGE_STUDIO_DB_PASSWORD", ""),
		StudioTLSDir:          env("SKYBRIDGE_STUDIO_TLS_DIR", ""),
		StudioTrustDomain:     env("SKYBRIDGE_STUDIO_SPIFFE_TRUST_DOMAIN", "curlix.studio-agent"),
		WireProxy:             LoadAgent(),
	}
}

// StudioEnabled reports whether the edge should dial the Studio Gateway (:7200).
func (e Edge) StudioEnabled() bool {
	return strings.TrimSpace(e.StudioGateway) != ""
}

// WireProxyEnabled reports whether the edge should also run the co-located DB wire proxy. Tunnel
// mode no longer requires a static target list — the gateway resolves targets live per connection.
func (e Edge) WireProxyEnabled() bool {
	switch e.WireProxy.Mode {
	case ModeTunnel:
		return e.WireProxy.GatewayAddr != ""
	default:
		return e.WireProxy.UpstreamAddr != ""
	}
}

// Gateway is the resolved configuration for the relay-side gateway.
type Gateway struct {
	AgentListen string           // address agents dial into (egress endpoint), e.g. ":8010"
	AuthToken   string           // required registration token (empty disables the check)
	Clients     []ClientListener // native-client listeners, each bound to a target

	// Session recording -> control plane (optional). When ControlPlaneURL is set the gateway reports
	// native-session lifecycle to the configured path; otherwise sessions are not recorded.
	ControlPlaneURL   string
	ControlPlaneToken string
	SessionPath       string // base path for session lifecycle reports (default /api/v1/data-studio/studio/native-sessions)
	WireAdmitPath     string // base path for wire client IP admission (default /api/v1/data-studio/studio/native-access/wire-admit)
	WireTargetPath    string // base path for live target resolution (default gateway.DefaultWireTargetPath)
	RequireOrgID      bool   // reject agent registration / client relay without organization_id
	ClientConnPerMin  int    // max new native client connections per client IP per minute (0 = unlimited)
	OrgConnPerMin     int    // max new native client connections per organization_id per minute (0 = unlimited)

	// ClientProxyProtocol: when true, every native-client listener expects a PROXY protocol v1/v2
	// header on each accepted connection (as sent by an AWS NLB target group with proxy_protocol_v2
	// enabled) and recovers the real client IP from it instead of trusting RemoteAddr() directly —
	// otherwise, behind an NLB, RemoteAddr() is always the NLB's own VPC-internal address, and the
	// per-org wire-admit IP allowlist check can never match a real client. Only enable this when the
	// NLB target group in front of these listeners actually sends PROXY protocol; a bare TCP client
	// connecting directly (no NLB) will fail the handshake and be dropped.
	ClientProxyProtocol bool

	// Wire-agent mTLS server side (Phase 2, docs/design/identity-aware-network-access.md). When a CA
	// bundle is configured, ListenAgents wraps the agent listener in a tls.Config that requires and
	// verifies agent client certs — the verified cert's SPIFFE identity replaces the plaintext
	// SKYBRIDGE_GW_TOKEN check in ServeAgent. Falls back to bearer-token mode when unset.
	WireMtlsCABundlePEM []byte // SKYBRIDGE_GW_MTLS_CA_BUNDLE_PEM / _FILE
	WireMtlsServerCert  []byte // SKYBRIDGE_GW_MTLS_SERVER_CERT_PEM / _FILE (self-signed generated if empty)
	WireMtlsServerKey   []byte // SKYBRIDGE_GW_MTLS_SERVER_KEY_PEM / _FILE
}

// WireMtlsConfigured reports whether the gateway should require agent client certs on its agent
// listener instead of (or on top of) the legacy bearer token.
func (g Gateway) WireMtlsConfigured() bool {
	return len(g.WireMtlsCABundlePEM) > 0
}

// ClientListener binds a local listen address to an org's registered target name. OrgID selects
// which org's agent tunnel serves this listener (one agent process per org); Target is resolved
// live per connection via the gateway's TargetResolver.
type ClientListener struct {
	Addr   string `json:"addr"`
	OrgID  string `json:"org_id"`
	Target string `json:"target"`
}

// LoadGateway reads the gateway config from the environment.
func LoadGateway() Gateway {
	cpURL := strings.TrimSpace(env("SKYBRIDGE_GW_CONTROL_PLANE_URL", ""))
	requireOrgID := truthy(env("SKYBRIDGE_GW_REQUIRE_ORG_ID", ""))
	if strings.TrimSpace(env("SKYBRIDGE_GW_REQUIRE_ORG_ID", "")) == "" && cpURL != "" {
		requireOrgID = true
	}
	clientConnPerMin := atoiDefault(env("SKYBRIDGE_GW_CLIENT_CONN_PER_MIN", ""), 0)
	orgConnPerMin := atoiDefault(env("SKYBRIDGE_GW_ORG_CONN_PER_MIN", ""), 0)
	if env("SKYBRIDGE_GW_CLIENT_CONN_PER_MIN", "") == "" && cpURL != "" {
		clientConnPerMin = 60
	}
	return Gateway{
		AgentListen:         env("SKYBRIDGE_GW_AGENT_LISTEN", ":8010"),
		AuthToken:           env("SKYBRIDGE_GW_TOKEN", ""),
		Clients:             parseClients(env("SKYBRIDGE_GW_CLIENTS", "")),
		ControlPlaneURL:     cpURL,
		ControlPlaneToken:   env("SKYBRIDGE_GW_CONTROL_PLANE_TOKEN", ""),
		SessionPath:         env("SKYBRIDGE_GW_SESSION_PATH", "/api/v1/data-studio/studio/native-sessions"),
		WireAdmitPath:       env("SKYBRIDGE_GW_WIRE_ADMIT_PATH", "/api/v1/data-studio/studio/native-access/wire-admit"),
		WireTargetPath:      env("SKYBRIDGE_GW_WIRE_TARGET_PATH", "/api/v1/data-studio/studio/native-access/wire-targets"),
		RequireOrgID:        requireOrgID,
		ClientConnPerMin:    clientConnPerMin,
		OrgConnPerMin:       orgConnPerMin,
		ClientProxyProtocol: truthy(env("SKYBRIDGE_GW_CLIENT_PROXY_PROTOCOL", "")),
		WireMtlsCABundlePEM: pemFromEnv("SKYBRIDGE_GW_MTLS_CA_BUNDLE_PEM", "SKYBRIDGE_GW_MTLS_CA_BUNDLE_FILE"),
		WireMtlsServerCert:  pemFromEnv("SKYBRIDGE_GW_MTLS_SERVER_CERT_PEM", "SKYBRIDGE_GW_MTLS_SERVER_CERT_FILE"),
		WireMtlsServerKey:   pemFromEnv("SKYBRIDGE_GW_MTLS_SERVER_KEY_PEM", "SKYBRIDGE_GW_MTLS_SERVER_KEY_FILE"),
	}
}

func parseClients(raw string) []ClientListener {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return nil
	}
	var cs []ClientListener
	if err := json.Unmarshal([]byte(raw), &cs); err != nil {
		return nil
	}
	return cs
}

func parseTargets(raw string) []tunnel.Target {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return nil
	}
	var ts []tunnel.Target
	if err := json.Unmarshal([]byte(raw), &ts); err != nil {
		return nil
	}
	for i := range ts {
		ts[i].DBType = strings.ToLower(ts[i].DBType)
	}
	return ts
}

func defaultListen(dbType string) string {
	switch dbType {
	case "mysql":
		return ":13306"
	case "mongodb", "mongo":
		return ":27018"
	default:
		return ":15432"
	}
}

func parseOverlay(raw string) map[string]string {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return nil
	}
	var m map[string]string
	if err := json.Unmarshal([]byte(raw), &m); err != nil {
		return nil
	}
	return m
}

func env(key, def string) string {
	if v := strings.TrimSpace(os.Getenv(key)); v != "" {
		return v
	}
	return def
}

// pemFromEnv returns PEM bytes from an inline env var, or from a file path env var, or nil.
func pemFromEnv(inlineKey, fileKey string) []byte {
	if inline := strings.TrimSpace(os.Getenv(inlineKey)); inline != "" {
		return []byte(inline)
	}
	if path := strings.TrimSpace(os.Getenv(fileKey)); path != "" {
		if b, err := os.ReadFile(path); err == nil {
			return b
		}
	}
	return nil
}

func truthy(v string) bool {
	switch strings.ToLower(strings.TrimSpace(v)) {
	case "1", "true", "yes", "on":
		return true
	default:
		return false
	}
}
