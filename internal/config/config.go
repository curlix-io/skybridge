// Package config loads Skybridge configuration from the environment. All keys are prefixed
// SKYBRIDGE_. The same binary runs as either an egress agent or a relay gateway depending on mode.
package config

import (
	"encoding/json"
	"log"
	"os"
	"strconv"
	"strings"

	"github.com/curlix-io/skybridge/internal/gateway"
	"github.com/curlix-io/skybridge/internal/mask"
	"github.com/curlix-io/skybridge/internal/tunnel"
	"gopkg.in/yaml.v3"
)

// Mode selects how the agent exposes databases.
const (
	ModeListener = "listener" // agent itself listens for native clients (clients reach the agent)
	ModeTunnel   = "tunnel"   // agent dials the relay gateway and serves streams over an egress tunnel
)

// Masking failure-handling modes (SKYBRIDGE_MASK_MODE). See Agent.MaskMode.
const (
	ModeBestEffort = "best-effort"
	ModeStrict     = "strict"
)

// Agent is the resolved configuration for an egress-side Skybridge agent.
type Agent struct {
	Mode     string // listener | tunnel
	LogLevel string // SKYBRIDGE_LOG_LEVEL: debug | info (default) | warn | error

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
	// MaskEntities restricts /analyze to these Presidio entity types (SKYBRIDGE_MASK_ENTITIES,
	// comma-separated, e.g. "EMAIL_ADDRESS,US_SSN,CREDIT_CARD"). Empty means the masker falls back
	// to a low-cost regex/rule-based default set rather than Presidio's all-45-recognizers default —
	// NER-backed types (PERSON, LOCATION, ORGANIZATION, NRP) require full spaCy inference per value
	// and are prone to false positives on ordinary business data (see Presidio's own docs for its
	// NER entity cost tiers). Opt into those explicitly.
	MaskEntities []string
	// MaskAnonymizers is Presidio's /anonymize "anonymizers" object verbatim (SKYBRIDGE_MASK_ANONYMIZERS,
	// JSON), letting each entity type get its own strategy (e.g. partial-mask SSNs, hash emails)
	// instead of one blanket replace. Empty uses a single DEFAULT replace-with-"[redacted]" rule.
	MaskAnonymizers map[string]any
	// MaskMode controls what happens when the remote masker itself fails (Presidio unreachable,
	// errors, malformed response) — SKYBRIDGE_MASK_MODE, "best-effort" (default) or "strict".
	// best-effort forwards the value unmasked so a masker outage never blocks legitimate queries.
	// strict fails the row/connection instead of ever letting unmasked content reach the client — a
	// posture other DLP-gated access proxies offer under their own equivalent strict mode. A
	// detection MISS (the masker ran fine and found nothing) is not a failure in either mode; only
	// masker errors are affected.
	MaskMode string
	// MaskAdHocRecognizers is Presidio's /analyze "ad_hoc_recognizers" array verbatim (see
	// mask.RemoteConfig.AdHocRecognizers), resolved from either SKYBRIDGE_MASK_RECOGNIZERS_YAML or
	// SKYBRIDGE_MASK_RECOGNIZERS_FILE via LoadRecognizers (internal/config/recognizers.go). Nil
	// disables custom recognizers (Presidio's built-in set only).
	MaskAdHocRecognizers []any
	// MaskAllowList is Presidio's /analyze "allow_list" (SKYBRIDGE_MASK_ALLOW_LIST, comma-separated,
	// case preserved since entries are literal values or patterns, not entity type names) — lets an
	// operator suppress a known-safe recurring false positive (e.g. a support line's own phone
	// number) without disabling an entire entity type or writing a custom recognizer. Static only:
	// unlike MaskEntities/MaskAdHocRecognizers, there is no control-plane dynamic-source equivalent
	// for this yet. Empty disables allow-listing (Presidio's own default of none).
	MaskAllowList []string
	// MaskAllowListMatch is Presidio's /analyze "allow_list_match" (SKYBRIDGE_MASK_ALLOW_LIST_MATCH):
	// "exact" (default) or "regex". Meaningless when MaskAllowList is empty.
	MaskAllowListMatch string
	// ConnectionRole tags this agent's masking-outcome metrics and connection-scoped recognizer
	// lookups (SKYBRIDGE_CONNECTION_ROLE, e.g. "primary", "readonly-replica") — combined with DBType
	// into metrics.ConnectionKey. Empty is a valid role (matches an org-wide/unscoped rule set).
	ConnectionRole string

	// Masking-outcome metrics (Data Classification dashboard). Off by default — MaskingMetricsURL
	// empty disables the recorder entirely (mask/metrics.Recorder.Enabled() reports false, every
	// Record* call is a no-op).
	MaskingMetricsURL         string // SKYBRIDGE_MASKING_METRICS_URL (POST endpoint)
	MaskingMetricsToken       string // SKYBRIDGE_MASKING_METRICS_TOKEN (defaults to SKYBRIDGE_TOKEN)
	MaskingMetricsPushSeconds int    // SKYBRIDGE_MASKING_METRICS_PUSH_SECONDS (0 -> metrics.minPushSeconds floor)

	// Dynamic custom-recognizers source (optional, control-plane "api_push" delivery mode). When
	// PIIRecognizersURL is set the agent fetches its org+driver+connection_role recognizer set at
	// startup and re-fetches on an interval, hot-swapping mask.Remote's ad-hoc recognizers. Falls
	// back to the static MaskAdHocRecognizers (SSM/file) when unset or on a failed fetch.
	PIIRecognizersURL         string // GET endpoint, e.g. https://app/api/v1/data-studio/studio/native-access/pii-recognizers
	PIIRecognizersToken       string // bearer token (defaults to SKYBRIDGE_TOKEN)
	PIIRecognizersPollSeconds int    // refresh interval in seconds (0 -> default; <0 -> fetch once)

	// Path-scoped PII label store (internal/pathlabel/remotestore), backing mask.PathOverlay. Unset
	// (PathLabelURL empty) leaves PathOverlay out of the masking chain entirely (see
	// buildMaskerWithOverlay's doc comment) — the "nothing configured -> mask.Noop" contract.
	PathLabelURL         string // pull/push base URL for confirmed + proposed labels
	PathLabelToken       string // bearer token (defaults to SKYBRIDGE_TOKEN)
	PathLabelPollSeconds int    // confirmed-label pull interval in seconds (floored at remotestore.minPollSeconds)
	PathLabelPushSeconds int    // proposed-label push interval in seconds (floored at remotestore.minPushSeconds)

	// Postgres table-identity resolution for PathOverlay (see REDACTION.md's "Postgres table-identity
	// resolution" design notes). RowDescription only carries a numeric tableOID, never a name, so
	// resolving it to a schema/table requires a pg_class/pg_namespace lookup the agent runs itself —
	// on a *separate* connection it opens and owns, never the client's own session (which would
	// corrupt that session's transaction/cursor state). PostgresCatalogDSN is a standard libpq
	// connection string/URL for a dedicated, read-only credential used only for that lookup — distinct
	// from the client's own login (which may be a per-session credential-injection secret, or simply a
	// credential this feature shouldn't need to depend on the client presenting). Empty disables this
	// resolution entirely: PathOverlay then behaves exactly as it does today for Postgres (empty
	// ObjectID, safe no-op, falls through to layer 3).
	PostgresCatalogDSN string // SKYBRIDGE_POSTGRES_CATALOG_DSN
	// PIIOverlay is the column->rule overlay you define (off by default): from SKYBRIDGE_PII_OVERLAY
	// (inline JSON, full-value replacement tokens only — see parseOverlay) or SKYBRIDGE_PII_OVERLAY_FILE
	// (a path to a YAML or JSON file — easier to author, diff, and commit than one-line JSON in an env
	// var; also the only form that accepts a partial-mask rule, e.g. {"credit_card": {"partial_mask":
	// true}} — see loadPIIOverlay). The file takes priority when both are set; an unreadable/invalid
	// file falls back to the inline env var rather than failing startup.
	PIIOverlay map[string]mask.OverlayRule

	// Dynamic overlay source (optional). When PIIOverlayURL is set the agent fetches the org's
	// projected column->token overlay from the control plane at startup and re-fetches on an
	// interval, hot-swapping the overlay rules — so native-client masking follows Administration →
	// PII edits without a redeploy. Falls back to the static PIIOverlay env when the fetch fails.
	PIIOverlayURL         string // GET endpoint, e.g. https://app/api/v1/data-studio/studio/native-access/pii-overlay
	PIIOverlayToken       string // bearer token for the fetch (defaults to SKYBRIDGE_TOKEN)
	PIIOverlayPollSeconds int    // refresh interval in seconds (0 → default 60; <0 → fetch once)
	// PIIOverlayOrgHeader overrides the request header carrying the org id on the dynamic overlay
	// fetch (SKYBRIDGE_PII_OVERLAY_ORG_HEADER). Empty uses agent.DefaultOrgHeader.
	PIIOverlayOrgHeader string

	// Credential handoff / injection. When enabled the agent terminates the native client's login
	// locally (the client presents an opaque session token as its password instead of a database
	// credential), exchanges that token with the control plane for a freshly-minted upstream
	// credential, and originates its own upstream auth. The client therefore never holds a credential
	// the database would accept directly. Disabled by default: the agent forwards the client's auth
	// verbatim, as before.
	InjectCredentials       bool   // SKYBRIDGE_INJECT_CREDENTIALS
	CredentialExchangeURL   string // SKYBRIDGE_CREDENTIAL_EXCHANGE_URL (POST endpoint on the control plane)
	CredentialExchangeToken string // bearer for the exchange call (defaults to SKYBRIDGE_TOKEN)
	// CredentialExchangePerMin caps exchange attempts per native-client IP per minute (0 =
	// unlimited). Without this, a client could open many connections and try many guessed session
	// tokens as the password with nothing in this codebase slowing repeated failures down.
	CredentialExchangePerMin int

	// Kubernetes API proxy credential exchange (docs/design/kubernetes-access-broker.md). Separate
	// URL from CredentialExchangeURL above: the K8s exchange resolves a bearer token per HTTP
	// request (no persistent login step), while the DB exchange resolves once per connection login —
	// different request/response shapes, so a distinct endpoint rather than overloading one.
	K8sCredentialExchangeURL string // SKYBRIDGE_K8S_CREDENTIAL_EXCHANGE_URL (defaults to unset — Kubernetes targets are unservable without it)
	// Client-side TLS termination for the Kubernetes API proxy target — always required (kubectl only
	// speaks HTTPS to a cluster API server; there is no plaintext client mode like Postgres/MySQL).
	K8sClientTLSCertPEM []byte // SKYBRIDGE_K8S_CLIENT_TLS_CERT_PEM / _FILE
	K8sClientTLSKeyPEM  []byte // SKYBRIDGE_K8S_CLIENT_TLS_KEY_PEM / _FILE

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
	WireMtlsEnrollURL   string // SKYBRIDGE_WIRE_MTLS_ENROLL_URL (control-plane origin, e.g. https://app.example.com)
	WireMtlsEnrollToken string // SKYBRIDGE_WIRE_MTLS_ENROLLMENT_TOKEN (one-time token to bootstrap the first cert)
	WireMtlsTLSDir      string // SKYBRIDGE_WIRE_MTLS_TLS_DIR (persists ca.pem/client.crt/client.key)
	WireMtlsCABundlePEM []byte // SKYBRIDGE_WIRE_MTLS_CA_BUNDLE_PEM / _FILE (pins the enroll call's server TLS)
	// WireMtlsTrustDomain is cosmetic (placed in the CSR SAN; the gateway's CA sets the
	// authoritative identity on signing) — sourced from the single SKYBRIDGE_TRUST_DOMAIN env var
	// shared with Edge.TrustDomain/StudioTrustDomain below. Empty falls back to this identity's own
	// default (wiremtls.DefaultTrustDomain) rather than one shared literal, so the three identities
	// stay distinguishable when nobody sets SKYBRIDGE_TRUST_DOMAIN at all.
	WireMtlsTrustDomain string
	// WireMtlsIdentitySecretARN mirrors the issued cert to this AWS Secrets Manager secret (see
	// certstore package) so a replaced task recovers its identity without a fresh enroll token.
	// WireMtlsIamAuthEnabled below is a stronger alternative for this same problem — no static
	// secret at all — and takes priority when both are set.
	WireMtlsIdentitySecretARN string // SKYBRIDGE_WIRE_MTLS_IDENTITY_SECRET_ARN

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

	// Session replay (see the session replay design doc). When enabled AND the gateway put a
	// SessionID on OpenMeta (control-plane session recording is on there too), the agent's wire
	// engines capture a transcript of already-masked input/output and flush it back over the
	// tunnel control channel on session end. Off by default — belt-and-suspenders alongside any
	// equivalent flag your control plane exposes, since this recorder runs on customer infra.
	// Tunnel mode only (listener mode has no control-plane session id).
	SessionReplayEnabled  bool // SKYBRIDGE_SESSION_REPLAY_ENABLED
	SessionReplayMaxBytes int  // SKYBRIDGE_SESSION_REPLAY_MAX_BYTES (0 → default 5 MiB)
}

// MaskStrict reports whether a masker failure should abort the row/connection (SKYBRIDGE_MASK_MODE=strict)
// rather than forward the value unmasked. Any value other than "strict" is treated as best-effort.
func (a Agent) MaskStrict() bool {
	return strings.ToLower(strings.TrimSpace(a.MaskMode)) == ModeStrict
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
		LogLevel:              env("SKYBRIDGE_LOG_LEVEL", ""),
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
		MaskEntities:          parseEntities(env("SKYBRIDGE_MASK_ENTITIES", "")),
		MaskAnonymizers:       parseAnonymizers(env("SKYBRIDGE_MASK_ANONYMIZERS", "")),
		MaskAllowList:         parseAllowList(env("SKYBRIDGE_MASK_ALLOW_LIST", "")),
		MaskAllowListMatch:    env("SKYBRIDGE_MASK_ALLOW_LIST_MATCH", "exact"),
		MaskMode:              strings.ToLower(env("SKYBRIDGE_MASK_MODE", ModeBestEffort)),
		PIIOverlay:            loadPIIOverlay(),
		PIIOverlayURL:         env("SKYBRIDGE_PII_OVERLAY_URL", ""),
		PIIOverlayToken:       env("SKYBRIDGE_PII_OVERLAY_TOKEN", env("SKYBRIDGE_TOKEN", "")),
		PIIOverlayPollSeconds: atoiDefault(env("SKYBRIDGE_PII_OVERLAY_POLL_SECONDS", ""), 60),
		PIIOverlayOrgHeader:   env("SKYBRIDGE_PII_OVERLAY_ORG_HEADER", ""),
		ConnectionRole:        env("SKYBRIDGE_CONNECTION_ROLE", ""),

		MaskingMetricsURL:         env("SKYBRIDGE_MASKING_METRICS_URL", ""),
		MaskingMetricsToken:       env("SKYBRIDGE_MASKING_METRICS_TOKEN", env("SKYBRIDGE_TOKEN", "")),
		MaskingMetricsPushSeconds: atoiDefault(env("SKYBRIDGE_MASKING_METRICS_PUSH_SECONDS", ""), 60),

		PIIRecognizersURL:         env("SKYBRIDGE_PII_RECOGNIZERS_URL", ""),
		PIIRecognizersToken:       env("SKYBRIDGE_PII_RECOGNIZERS_TOKEN", env("SKYBRIDGE_TOKEN", "")),
		PIIRecognizersPollSeconds: atoiDefault(env("SKYBRIDGE_PII_RECOGNIZERS_POLL_SECONDS", ""), 60),

		PathLabelURL:         env("SKYBRIDGE_PATH_LABEL_URL", ""),
		PathLabelToken:       env("SKYBRIDGE_PATH_LABEL_TOKEN", env("SKYBRIDGE_TOKEN", "")),
		PathLabelPollSeconds: atoiDefault(env("SKYBRIDGE_PATH_LABEL_POLL_SECONDS", ""), 60),
		PathLabelPushSeconds: atoiDefault(env("SKYBRIDGE_PATH_LABEL_PUSH_SECONDS", ""), 15),
		PostgresCatalogDSN:   env("SKYBRIDGE_POSTGRES_CATALOG_DSN", ""),

		InjectCredentials:        truthy(env("SKYBRIDGE_INJECT_CREDENTIALS", "")),
		CredentialExchangeURL:    env("SKYBRIDGE_CREDENTIAL_EXCHANGE_URL", ""),
		CredentialExchangeToken:  env("SKYBRIDGE_CREDENTIAL_EXCHANGE_TOKEN", env("SKYBRIDGE_TOKEN", "")),
		CredentialExchangePerMin: atoiDefault(env("SKYBRIDGE_CREDENTIAL_EXCHANGE_PER_MIN", ""), 0),

		K8sCredentialExchangeURL: env("SKYBRIDGE_K8S_CREDENTIAL_EXCHANGE_URL", ""),
		K8sClientTLSCertPEM:      pemFromEnv("SKYBRIDGE_K8S_CLIENT_TLS_CERT_PEM", "SKYBRIDGE_K8S_CLIENT_TLS_CERT_FILE"),
		K8sClientTLSKeyPEM:       pemFromEnv("SKYBRIDGE_K8S_CLIENT_TLS_KEY_PEM", "SKYBRIDGE_K8S_CLIENT_TLS_KEY_FILE"),

		ClientTLSCertPEM:    pemFromEnv("SKYBRIDGE_CLIENT_TLS_CERT_PEM", "SKYBRIDGE_CLIENT_TLS_CERT_FILE"),
		ClientTLSKeyPEM:     pemFromEnv("SKYBRIDGE_CLIENT_TLS_KEY_PEM", "SKYBRIDGE_CLIENT_TLS_KEY_FILE"),
		ClientTLSSelfSigned: truthy(env("SKYBRIDGE_CLIENT_TLS_SELF_SIGNED", "")),

		UpstreamTLSMode:       strings.ToLower(env("SKYBRIDGE_UPSTREAM_TLS", "")),
		UpstreamTLSCAPEM:      pemFromEnv("SKYBRIDGE_UPSTREAM_TLS_CA_PEM", "SKYBRIDGE_UPSTREAM_TLS_CA_FILE"),
		UpstreamTLSServerName: env("SKYBRIDGE_UPSTREAM_TLS_SERVER_NAME", ""),

		WireMtlsEnrollURL:         env("SKYBRIDGE_WIRE_MTLS_ENROLL_URL", ""),
		WireMtlsEnrollToken:       env("SKYBRIDGE_WIRE_MTLS_ENROLLMENT_TOKEN", ""),
		WireMtlsTLSDir:            env("SKYBRIDGE_WIRE_MTLS_TLS_DIR", ""),
		WireMtlsCABundlePEM:       pemFromEnv("SKYBRIDGE_WIRE_MTLS_CA_BUNDLE_PEM", "SKYBRIDGE_WIRE_MTLS_CA_BUNDLE_FILE"),
		WireMtlsTrustDomain:       env("SKYBRIDGE_TRUST_DOMAIN", ""),
		WireMtlsIdentitySecretARN: env("SKYBRIDGE_WIRE_MTLS_IDENTITY_SECRET_ARN", ""),

		WireMtlsClientCertPEM: pemFromEnv("SKYBRIDGE_WIRE_MTLS_CLIENT_CERT_PEM", "SKYBRIDGE_WIRE_MTLS_CLIENT_CERT_FILE"),
		WireMtlsClientKeyPEM:  pemFromEnv("SKYBRIDGE_WIRE_MTLS_CLIENT_KEY_PEM", "SKYBRIDGE_WIRE_MTLS_CLIENT_KEY_FILE"),

		WireMtlsIamAuthEnabled: truthy(env("SKYBRIDGE_WIRE_MTLS_IAM_AUTH", "")),

		SessionReplayEnabled:  truthy(env("SKYBRIDGE_SESSION_REPLAY_ENABLED", "")),
		SessionReplayMaxBytes: atoiDefault(env("SKYBRIDGE_SESSION_REPLAY_MAX_BYTES", ""), 5<<20),
	}
	if recognizers, err := LoadRecognizers(
		env("SKYBRIDGE_MASK_RECOGNIZERS_YAML", ""),
		env("SKYBRIDGE_MASK_RECOGNIZERS_FILE", ""),
	); err != nil {
		log.Printf("skybridge: SKYBRIDGE_MASK_RECOGNIZERS_YAML/_FILE: %v (custom recognizers disabled)", err)
	} else {
		a.MaskAdHocRecognizers = recognizers
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
	LogLevel string // SKYBRIDGE_LOG_LEVEL: debug | info (default) | warn | error

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
	// TrustDomain is cosmetic (placed in the CSR SAN only; the gateway's CA sets the authoritative
	// identity on signing) — sourced from the single SKYBRIDGE_TRUST_DOMAIN env var, shared with
	// StudioTrustDomain/WireProxy.WireMtlsTrustDomain below. Empty falls back to this identity's own
	// default (transport.DefaultTrustDomain) rather than one shared literal.
	TrustDomain string
	// IdentitySecretARN, when set, mirrors the issued cert to this AWS Secrets Manager secret so a
	// replaced ECS task recovers its identity instead of re-enrolling with an already-used one-time
	// token. See SKYBRIDGE_IDENTITY_SECRET_ARN.
	IdentitySecretARN string

	// Live read-only AWS access (executed locally at the edge).
	AWSRegion        string
	AWSAssumeRoleARN string
	AWSExternalID    string
	AWSBinary        string

	// Governed kubectl access (executed locally at the edge — see internal/edge/k8sexec).
	K8sKubeconfig string
	K8sContext    string
	K8sBinary     string

	// Studio execution agent (Query Studio dispatch, on :7200).
	StudioGateway         string // SKYBRIDGE_STUDIO_GATEWAY host:port
	StudioEnrollGateway   string // SKYBRIDGE_STUDIO_ENROLL_GATEWAY (defaults to StudioGateway)
	StudioEnrollmentToken string
	StudioAgentID         string
	StudioMaxSessions     int
	StudioTargetsJSON     string
	StudioDBUser          string
	StudioDBPassword      string
	StudioTLSDir          string
	// StudioTrustDomain is cosmetic (see TrustDomain above) — also sourced from SKYBRIDGE_TRUST_DOMAIN.
	// Empty falls back to studiotransport's own default rather than one shared literal.
	StudioTrustDomain string
	// StudioIdentitySecretARN mirrors StudioTLSDir's cert to Secrets Manager. See
	// SKYBRIDGE_STUDIO_IDENTITY_SECRET_ARN.
	StudioIdentitySecretARN string

	// Optional co-located wire proxy. When non-empty the edge also runs the DB proxy (see Agent).
	WireProxy Agent
}

// LoadEdge reads the unified edge config from the environment. When SKYBRIDGE_KEY is set (a
// single skybridge://org:token@host DSN, see dsn.go), its decoded fields seed the defaults below —
// any discrete SKYBRIDGE_* var still takes priority over the key, so existing deployments and the
// CloudFormation/mTLS-enroll paths (which don't use a key at all) are unaffected.
func LoadEdge() Edge {
	key, err := parseEdgeKey(env("SKYBRIDGE_KEY", ""))
	if err != nil {
		log.Printf("skybridge-edge: %v — ignoring SKYBRIDGE_KEY", err)
		key = EdgeKey{}
	}
	caBundle := pemFromEnv("SKYBRIDGE_CA_BUNDLE_PEM", "SKYBRIDGE_CA_BUNDLE_FILE")
	if len(caBundle) == 0 {
		caBundle = key.CABundlePEM
	}
	return Edge{
		LogLevel:                env("SKYBRIDGE_LOG_LEVEL", ""),
		GatewayAddr:             env("SKYBRIDGE_EDGE_GATEWAY", env("SKYBRIDGE_GATEWAY", hostPort(key.GatewayHost, "7100"))),
		TenantID:                env("SKYBRIDGE_ORG_ID", key.OrgID),
		EdgeID:                  env("SKYBRIDGE_EDGE_ID", env("SKYBRIDGE_AGENT_ID", key.EdgeID)),
		Token:                   env("SKYBRIDGE_TOKEN", key.EnrollmentToken),
		Insecure:                truthy(env("SKYBRIDGE_EDGE_INSECURE", "")),
		CABundle:                caBundle,
		TLSDir:                  env("SKYBRIDGE_TLS_DIR", ""),
		EnrollTarget:            env("SKYBRIDGE_ENROLL_GATEWAY", hostPort(key.GatewayHost, "7101")),
		EnrollToken:             env("SKYBRIDGE_ENROLLMENT_TOKEN", key.EnrollmentToken),
		TrustDomain:             env("SKYBRIDGE_TRUST_DOMAIN", ""),
		IdentitySecretARN:       env("SKYBRIDGE_IDENTITY_SECRET_ARN", ""),
		AWSRegion:               env("SKYBRIDGE_AWS_REGION", key.AWSRegion),
		AWSAssumeRoleARN:        env("SKYBRIDGE_AWS_ASSUME_ROLE_ARN", ""),
		AWSExternalID:           env("SKYBRIDGE_AWS_EXTERNAL_ID", ""),
		AWSBinary:               env("SKYBRIDGE_AWS_BINARY", ""),
		K8sKubeconfig:           env("SKYBRIDGE_K8S_KUBECONFIG", ""),
		K8sContext:              env("SKYBRIDGE_K8S_CONTEXT", ""),
		K8sBinary:               env("SKYBRIDGE_K8S_BINARY", ""),
		StudioGateway:           env("SKYBRIDGE_STUDIO_GATEWAY", ""),
		StudioEnrollGateway:     env("SKYBRIDGE_STUDIO_ENROLL_GATEWAY", ""),
		StudioEnrollmentToken:   env("SKYBRIDGE_STUDIO_ENROLLMENT_TOKEN", ""),
		StudioAgentID:           env("SKYBRIDGE_STUDIO_AGENT_ID", env("SKYBRIDGE_EDGE_ID", "")),
		StudioMaxSessions:       atoiDefault(env("SKYBRIDGE_STUDIO_MAX_SESSIONS", "8"), 8),
		StudioTargetsJSON:       env("SKYBRIDGE_STUDIO_TARGETS", ""),
		StudioDBUser:            env("SKYBRIDGE_STUDIO_DB_USER", ""),
		StudioDBPassword:        env("SKYBRIDGE_STUDIO_DB_PASSWORD", ""),
		StudioTLSDir:            env("SKYBRIDGE_STUDIO_TLS_DIR", ""),
		StudioTrustDomain:       env("SKYBRIDGE_TRUST_DOMAIN", ""),
		StudioIdentitySecretARN: env("SKYBRIDGE_STUDIO_IDENTITY_SECRET_ARN", ""),
		WireProxy:               LoadAgent(),
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
	LogLevel string // SKYBRIDGE_LOG_LEVEL: debug | info (default) | warn | error

	AgentListen string           // address agents dial into (egress endpoint), e.g. ":8010"
	AuthToken   string           // required registration token (empty disables the check)
	Clients     []ClientListener // native-client listeners, each bound to a target

	// Session recording -> control plane (optional). When ControlPlaneURL is set the gateway reports
	// native-session lifecycle to the configured path; otherwise sessions are not recorded.
	ControlPlaneURL   string
	ControlPlaneToken string
	SessionPath       string // base path for session lifecycle reports (default gateway.DefaultSessionPath)
	WireAdmitPath     string // base path for wire client IP admission (default gateway.DefaultWireAdmitPath)
	WireTargetPath    string // base path for live target resolution (default gateway.DefaultWireTargetPath)
	RequireOrgID      bool   // reject agent registration / client relay without organization_id
	ClientConnPerMin  int    // max new native client connections per client IP per minute (0 = unlimited)
	OrgConnPerMin     int    // max new native client connections per organization_id per minute (0 = unlimited)
	// OrgMaxConcurrentClients caps how many client connections one organization_id can have
	// relayed *simultaneously* through this gateway (0 = unlimited). ClientConnPerMin/OrgConnPerMin
	// above only throttle the *rate* of new connections — nothing stops one org from opening that
	// many connections and simply never closing them, holding goroutines/fds/tunnel-stream slots
	// indefinitely at every other org's expense. This bounds the standing total instead.
	OrgMaxConcurrentClients int
	// AgentConnPerMin caps agent *registration* attempts per client IP per minute (0 = unlimited).
	// Distinct from ClientConnPerMin/OrgConnPerMin above (which gate native-client connections):
	// without this, the agent listener's bearer-token check can be probed at whatever rate TCP
	// handshakes allow.
	AgentConnPerMin int

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

// ClientListener binds a local listen address to an org's wire database protocol. OrgID selects
// which org's agent tunnel serves this listener (one agent process per org); Target is the
// listener's fixed db_type (postgres | mysql | mongodb | snowflake — matches the listener's own
// port, never renamed) and is resolved live per connection via the gateway's TargetResolver.
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
	orgMaxConcurrentClients := atoiDefault(env("SKYBRIDGE_GW_ORG_MAX_CONCURRENT_CLIENTS", ""), 0)
	if env("SKYBRIDGE_GW_CLIENT_CONN_PER_MIN", "") == "" && cpURL != "" {
		clientConnPerMin = 60
	}
	// Same auto-default posture as ClientConnPerMin above: a stock deployment with a control plane
	// configured gets a sane, generous ceiling (well above any legitimate single org's real
	// concurrent-connection count) rather than staying fully unlimited; a bare/self-hosted gateway
	// with no control plane stays unlimited unless the operator opts in explicitly.
	if env("SKYBRIDGE_GW_ORG_MAX_CONCURRENT_CLIENTS", "") == "" && cpURL != "" {
		orgMaxConcurrentClients = 1000
	}
	return Gateway{
		LogLevel:                env("SKYBRIDGE_LOG_LEVEL", ""),
		AgentListen:             env("SKYBRIDGE_GW_AGENT_LISTEN", ":8010"),
		AuthToken:               env("SKYBRIDGE_GW_TOKEN", ""),
		Clients:                 parseClients(env("SKYBRIDGE_GW_CLIENTS", "")),
		ControlPlaneURL:         cpURL,
		ControlPlaneToken:       env("SKYBRIDGE_GW_CONTROL_PLANE_TOKEN", ""),
		SessionPath:             env("SKYBRIDGE_GW_SESSION_PATH", gateway.DefaultSessionPath),
		WireAdmitPath:           env("SKYBRIDGE_GW_WIRE_ADMIT_PATH", gateway.DefaultWireAdmitPath),
		WireTargetPath:          env("SKYBRIDGE_GW_WIRE_TARGET_PATH", gateway.DefaultWireTargetPath),
		RequireOrgID:            requireOrgID,
		ClientConnPerMin:        clientConnPerMin,
		OrgConnPerMin:           orgConnPerMin,
		OrgMaxConcurrentClients: orgMaxConcurrentClients,
		AgentConnPerMin:         atoiDefault(env("SKYBRIDGE_GW_AGENT_CONN_PER_MIN", ""), 0),
		ClientProxyProtocol:     truthy(env("SKYBRIDGE_GW_CLIENT_PROXY_PROTOCOL", "")),
		WireMtlsCABundlePEM:     pemFromEnv("SKYBRIDGE_GW_MTLS_CA_BUNDLE_PEM", "SKYBRIDGE_GW_MTLS_CA_BUNDLE_FILE"),
		WireMtlsServerCert:      pemFromEnv("SKYBRIDGE_GW_MTLS_SERVER_CERT_PEM", "SKYBRIDGE_GW_MTLS_SERVER_CERT_FILE"),
		WireMtlsServerKey:       pemFromEnv("SKYBRIDGE_GW_MTLS_SERVER_KEY_PEM", "SKYBRIDGE_GW_MTLS_SERVER_KEY_FILE"),
	}
}

// Labeller is the resolved configuration for skybridge-labeller, the periodic AI-based path-label
// scan job (internal/pathlabel/aiclassifier) — see docs/AI_PATH_LABELLING_DESIGN.md. Distinct from
// Agent/Gateway because it's a separate process with no wire-proxy or client-listener concerns of
// its own; it only samples a database on a schedule and proposes labels to the control plane.
type Labeller struct {
	LogLevel string // SKYBRIDGE_LOG_LEVEL: debug | info (default) | warn | error

	OrgID string // tenant this scan job proposes labels for; required
	Token string // bearer token (defaults to SKYBRIDGE_TOKEN)

	// DBType/DSN identify the one database this run samples — SKYBRIDGE_LABELLER_DB_TYPE (postgres |
	// mysql | snowflake | mongo) and SKYBRIDGE_LABELLER_DSN (a read-only credential's connection
	// string — a database/sql DSN for postgres/mysql/snowflake, a mongodb:// URI for mongo —
	// analogous to SKYBRIDGE_POSTGRES_CATALOG_DSN's "dedicated, read-only, independent of any client
	// session" posture; this DSN is never the same credential a native client's session uses).
	DBType string
	DSN    string
	// Database is the logical database name embedded in the resulting ObjectID
	// ("{org}:{driver}:{database}:{table}", matching internal/edge/dbquery's objectID convention),
	// since a DSN's own embedded database name isn't reliably recoverable from every driver's DSN
	// syntax.
	Database string
	// Tables is the set of tables (or, for DBType=mongo, collections) to scan every run
	// (SKYBRIDGE_LABELLER_TABLES, comma-separated). Optional — when empty, Run discovers every
	// table/collection in Database itself (sqlsampler.ListTables' information_schema.tables query,
	// or mongosampler.ListTables' ListCollectionNames), so this job doesn't need an
	// operator-maintained list to notice a newly-created table. An explicit list still takes
	// priority when set, e.g. to scope this job to a known-sensitive subset. For Mongo, which has no
	// fixed schema at all for field discovery (only for the collection list itself),
	// internal/pathlabel/mongosampler.ListColumns discovers each named collection's observed fields
	// per scan rather than reading a catalog.
	Tables []string
	// MaxSamplesPerField bounds how many non-null values are read per table column per scan —
	// SKYBRIDGE_LABELLER_MAX_SAMPLES (default aiclassifier.defaultMaxSamples via 0).
	MaxSamplesPerField int
	// MaxObjectsPerScan bounds how many tables/collections one scan cycle actually samples —
	// SKYBRIDGE_LABELLER_MAX_OBJECTS_PER_SCAN (default 50; <= 0 means unlimited). Without this, a
	// schema with tens of thousands of tables would fan out into a proportional number of LLM
	// Classify calls every single cycle — see docs/AI_PATH_LABELLING_DESIGN.md §5.5's "bound sample
	// count and scan frequency" note, extended here to bound scan *breadth* the same way. Combined
	// with RescanIntervalSeconds, internal/labeller's scheduler round-robins: each cycle picks the
	// least-recently-scanned eligible tables first, so a large schema is covered incrementally
	// across many cycles rather than needing one cycle to cover it all.
	MaxObjectsPerScan int
	// RescanIntervalSeconds skips a table/collection this cycle if it was already scanned within
	// this many seconds — SKYBRIDGE_LABELLER_RESCAN_INTERVAL_SECONDS (default 86400; <= 0 disables
	// skipping, rescanning every eligible object every cycle same as before this field existed). A
	// table's column shape and PII classification rarely change hour to hour, so there's little
	// value in re-running a full LLM classification pass on it every ScanIntervalSeconds once it's
	// been covered recently — this frees MaxObjectsPerScan's budget for tables not yet seen.
	RescanIntervalSeconds int
	// ScanIntervalSeconds is how often the full table list is rescanned — SKYBRIDGE_LABELLER_SCAN_INTERVAL_SECONDS
	// (floored, see labellerMinScanIntervalSeconds — this is a periodic background job, not a
	// once-per-second poll).
	ScanIntervalSeconds int

	// LLM classifier backend (internal/pathlabel/aiclassifier.LLM) — see
	// docs/AI_PATH_LABELLING_DESIGN.md §5.1a/§8 item 1. Endpoint is required for this binary to do
	// anything; unset, LoadLabeller still returns a value (so -help works) but main.go refuses to
	// start the scan loop.
	LLMEndpoint      string   // SKYBRIDGE_LABELLER_LLM_ENDPOINT
	LLMAPIKey        string   // SKYBRIDGE_LABELLER_LLM_API_KEY
	LLMCategories    []string // SKYBRIDGE_LABELLER_LLM_CATEGORIES, comma-separated taxonomy — required alongside Endpoint
	LLMMinConfidence float64  // SKYBRIDGE_LABELLER_LLM_MIN_CONFIDENCE (0 accepts any response)

	// Path-label propose endpoint (internal/pathlabel/remotestore) — same control-plane contract
	// mask.PathOverlay's confirmed-label pull already uses; this job only ever pushes proposals
	// through it, per SourceProposed's "never redacts on its own" contract.
	PathLabelURL         string
	PathLabelToken       string
	PathLabelPollSeconds int
	PathLabelPushSeconds int
}

// labellerMinScanIntervalSeconds floors SKYBRIDGE_LABELLER_SCAN_INTERVAL_SECONDS — this job samples
// live rows from the target database on every run; a floor keeps a misconfigured low value from
// turning the "periodic, off the query hot path" job (docs/AI_PATH_LABELLING_DESIGN.md §5.2) into
// something that competes with real traffic for the read-only credential.
const labellerMinScanIntervalSeconds = 300

// LoadLabeller reads skybridge-labeller's config from the environment.
func LoadLabeller() Labeller {
	return Labeller{
		LogLevel:              env("SKYBRIDGE_LOG_LEVEL", ""),
		OrgID:                 env("SKYBRIDGE_ORG_ID", ""),
		Token:                 env("SKYBRIDGE_TOKEN", ""),
		DBType:                strings.ToLower(env("SKYBRIDGE_LABELLER_DB_TYPE", "postgres")),
		DSN:                   env("SKYBRIDGE_LABELLER_DSN", ""),
		Database:              env("SKYBRIDGE_LABELLER_DATABASE", ""),
		Tables:                splitCSV(env("SKYBRIDGE_LABELLER_TABLES", "")),
		MaxSamplesPerField:    atoiDefault(env("SKYBRIDGE_LABELLER_MAX_SAMPLES", ""), 0),
		MaxObjectsPerScan:     atoiDefault(env("SKYBRIDGE_LABELLER_MAX_OBJECTS_PER_SCAN", ""), 50),
		RescanIntervalSeconds: atoiDefault(env("SKYBRIDGE_LABELLER_RESCAN_INTERVAL_SECONDS", ""), 86400),
		ScanIntervalSeconds:   max(atoiDefault(env("SKYBRIDGE_LABELLER_SCAN_INTERVAL_SECONDS", ""), 3600), labellerMinScanIntervalSeconds),

		LLMEndpoint:      env("SKYBRIDGE_LABELLER_LLM_ENDPOINT", ""),
		LLMAPIKey:        env("SKYBRIDGE_LABELLER_LLM_API_KEY", ""),
		LLMCategories:    splitCSV(env("SKYBRIDGE_LABELLER_LLM_CATEGORIES", "")),
		LLMMinConfidence: atofDefault(env("SKYBRIDGE_LABELLER_LLM_MIN_CONFIDENCE", ""), 0.5),

		PathLabelURL:         env("SKYBRIDGE_PATH_LABEL_URL", ""),
		PathLabelToken:       env("SKYBRIDGE_PATH_LABEL_TOKEN", env("SKYBRIDGE_TOKEN", "")),
		PathLabelPollSeconds: atoiDefault(env("SKYBRIDGE_PATH_LABEL_POLL_SECONDS", ""), 60),
		PathLabelPushSeconds: atoiDefault(env("SKYBRIDGE_PATH_LABEL_PUSH_SECONDS", ""), 15),
	}
}

func splitCSV(raw string) []string {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return nil
	}
	parts := strings.Split(raw, ",")
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		if p = strings.TrimSpace(p); p != "" {
			out = append(out, p)
		}
	}
	return out
}

func atofDefault(raw string, def float64) float64 {
	if raw == "" {
		return def
	}
	f, err := strconv.ParseFloat(raw, 64)
	if err != nil {
		return def
	}
	return f
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

func parseEntities(raw string) []string {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return nil
	}
	var out []string
	for _, part := range strings.Split(raw, ",") {
		part = strings.ToUpper(strings.TrimSpace(part))
		if part != "" {
			out = append(out, part)
		}
	}
	return out
}

// parseAllowList splits SKYBRIDGE_MASK_ALLOW_LIST on commas, trimming whitespace around each entry
// but preserving case — unlike parseEntities, entries here are literal values or regex patterns
// (an email address, a phone number), not entity type names, so case is meaningful.
func parseAllowList(raw string) []string {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return nil
	}
	var out []string
	for _, part := range strings.Split(raw, ",") {
		part = strings.TrimSpace(part)
		if part != "" {
			out = append(out, part)
		}
	}
	return out
}

func parseAnonymizers(raw string) map[string]any {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return nil
	}
	var m map[string]any
	if err := json.Unmarshal([]byte(raw), &m); err != nil {
		log.Printf("skybridge: invalid SKYBRIDGE_MASK_ANONYMIZERS (ignoring): %v", err)
		return nil
	}
	return m
}

// parseOverlay parses the inline SKYBRIDGE_PII_OVERLAY env var — string values (full-value
// replacement tokens) only, matching its shape from before OverlayRule existed. Only
// SKYBRIDGE_PII_OVERLAY_FILE (see loadPIIOverlay) accepts the richer partial-mask rule shape; a
// value in the inline JSON that isn't a plain string is skipped with a warning rather than
// silently coerced or failing the whole overlay.
func parseOverlay(raw string) map[string]mask.OverlayRule {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return nil
	}
	var m map[string]string
	if err := json.Unmarshal([]byte(raw), &m); err != nil {
		log.Printf("skybridge: invalid SKYBRIDGE_PII_OVERLAY (ignoring): %v", err)
		return nil
	}
	out := make(map[string]mask.OverlayRule, len(m))
	for k, v := range m {
		out[k] = mask.OverlayRule{Token: v}
	}
	return out
}

// overlayRuleFromAny interprets one SKYBRIDGE_PII_OVERLAY_FILE value: a plain string is a
// full-value replacement token (OverlayRule.Token, unchanged from before OverlayRule existed); a
// mapping with partial_mask: true opts that column into partial masking (OverlayRule.Partial) —
// keep the value's last few characters, mask the rest (see mask.partialMask's fixed default). Any
// other shape (a number, a list, a mapping without partial_mask: true) has ok=false so the caller
// can skip just that key rather than discard the whole file over one bad rule.
func overlayRuleFromAny(v any) (mask.OverlayRule, bool) {
	switch val := v.(type) {
	case string:
		return mask.OverlayRule{Token: val}, true
	case map[string]any:
		if partial, _ := val["partial_mask"].(bool); partial {
			return mask.OverlayRule{Partial: true}, true
		}
	}
	return mask.OverlayRule{}, false
}

// loadPIIOverlay resolves the column->rule overlay from SKYBRIDGE_PII_OVERLAY_FILE (a YAML or JSON
// file — friendlier to author/review/commit than one-line JSON in an env var, and the only form
// that accepts a partial-mask rule — see overlayRuleFromAny) when set, otherwise from the inline
// SKYBRIDGE_PII_OVERLAY env var (see parseOverlay). The file path wins if both are set.
func loadPIIOverlay() map[string]mask.OverlayRule {
	path := strings.TrimSpace(os.Getenv("SKYBRIDGE_PII_OVERLAY_FILE"))
	if path == "" {
		return parseOverlay(env("SKYBRIDGE_PII_OVERLAY", ""))
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		log.Printf("skybridge: SKYBRIDGE_PII_OVERLAY_FILE %q: %v (ignoring)", path, err)
		return parseOverlay(env("SKYBRIDGE_PII_OVERLAY", ""))
	}
	var m map[string]any
	if err := yaml.Unmarshal(raw, &m); err != nil {
		log.Printf("skybridge: SKYBRIDGE_PII_OVERLAY_FILE %q: invalid YAML/JSON: %v (ignoring)", path, err)
		return parseOverlay(env("SKYBRIDGE_PII_OVERLAY", ""))
	}
	out := make(map[string]mask.OverlayRule, len(m))
	for k, v := range m {
		rule, ok := overlayRuleFromAny(v)
		if !ok {
			log.Printf("skybridge: SKYBRIDGE_PII_OVERLAY_FILE %q: column %q has an unrecognized rule shape (skipping)", path, k)
			continue
		}
		out[k] = rule
	}
	return out
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
