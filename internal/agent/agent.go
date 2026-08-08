// Package agent runs the egress-side Skybridge data plane in either deployment mode:
//
//   - listener: the agent listens locally for native clients (psql/mysql/mongosh) and proxies to the
//     upstream DB, masking result rows. Clients reach the agent directly.
//   - tunnel:   the agent dials OUT to the relay gateway (egress-only), registers the targets it can
//     reach, and serves the gateway's logical streams by running the same wire engines + masker
//     against the upstream DB. Raw data never leaves the egress network.
//
// Both modes share the engine selection and masking pipeline, so masking behaviour is identical no
// matter how the client arrives.
package agent

import (
	"context"
	"crypto/tls"
	"fmt"
	"log"
	"net"
	"time"

	"github.com/curlix-io/skybridge/internal/config"
	"github.com/curlix-io/skybridge/internal/mask"
	"github.com/curlix-io/skybridge/internal/tunnel"
	"github.com/curlix-io/skybridge/internal/wire"
	"github.com/curlix-io/skybridge/internal/wiremtls"
)

const (
	dialTimeout       = 10 * time.Second
	heartbeatInterval = 15 * time.Second
)

// Deps are injectable collaborators (overridable in tests); zero values fall back to real defaults.
type Deps struct {
	Dial        func(ctx context.Context, network, addr string) (net.Conn, error)
	Engine      func(dbType string) (wire.Engine, error)
	Masker      mask.Masker
	Resolver    wire.CredentialResolver // non-nil enables credential injection (handoff)
	UpstreamTLS *upstreamTLSPolicy      // non-nil enables agent→database TLS (Postgres)
}

func (d Deps) withDefaults(cfg config.Agent) Deps {
	if d.Dial == nil {
		dialer := &net.Dialer{Timeout: dialTimeout}
		d.Dial = dialer.DialContext
	}
	if d.Engine == nil {
		d.Engine = EngineFor
	}
	if d.Masker == nil {
		d.Masker = BuildMasker(cfg)
	}
	if d.Resolver == nil {
		// nil when injection is not configured → the verbatim Proxy path is used.
		d.Resolver = NewHTTPCredentialResolver(cfg)
	}
	return d
}

// proxyConn runs the right proxy path for one session: the credential-injection path when a resolver
// is configured and the engine supports it, otherwise the verbatim passthrough that forwards the
// client's own auth to the upstream.
func proxyConn(ctx context.Context, engine wire.Engine, client, upstream net.Conn, masker mask.Masker, resolver wire.CredentialResolver, recorder wire.Recorder) error {
	if resolver != nil {
		if ie, ok := engine.(wire.InjectingEngine); ok {
			return ie.ProxyInject(ctx, client, upstream, masker, resolver, recorder)
		}
	}
	return engine.Proxy(ctx, client, upstream, masker, recorder)
}

// EngineFor selects a wire engine by database type (no client-TLS termination). The agent uses the
// TLS-aware engineFactory at runtime; this stays for callers/tests that want the plaintext default.
func EngineFor(dbType string) (wire.Engine, error) {
	return engineFactory(nil)(dbType)
}

// BuildMasker assembles the masking chain (remote masker + your column overlay) from config.
func BuildMasker(cfg config.Agent) mask.Masker {
	m, _ := buildMaskerWithOverlay(cfg)
	return m
}

// buildMaskerWithOverlay assembles the masking chain and returns the overlay handle so a dynamic
// source can hot-swap its rules. The overlay layer is included when a static overlay is configured
// OR a dynamic source URL is set (so later refreshes take effect even if the seed is empty); the
// handle is nil when no overlay layer is active.
func buildMaskerWithOverlay(cfg config.Agent) (mask.Masker, *mask.Overlay) {
	var maskers []mask.Masker
	remote := mask.NewRemote(mask.RemoteConfig{
		AnalyzeURL:   cfg.MaskAnalyzeURL,
		AnonymizeURL: cfg.MaskAnonymizeURL,
		Language:     cfg.MaskLanguage,
		Entities:     cfg.MaskEntities,
		Anonymizers:  cfg.MaskAnonymizers,
		Strict:       cfg.MaskStrict(),
	})
	if remote.Enabled() {
		maskers = append(maskers, remote)
	}
	var overlay *mask.Overlay
	if len(cfg.PIIOverlay) > 0 || cfg.PIIOverlayURL != "" {
		overlay = mask.NewOverlay(cfg.PIIOverlay)
		maskers = append(maskers, overlay)
	}
	if len(maskers) == 0 {
		return mask.Noop{}, nil
	}
	return mask.NewChain(maskers...), overlay
}

// logMaskingGuardrails emits startup warnings when the configured masking posture is weaker than an
// operator likely intends. By default (SKYBRIDGE_MASK_MODE=best-effort) the wire proxy is fail-open
// — a masker miss or outage forwards the value unchanged — so a missing layer silently lets data
// through; these logs make that explicit at boot. SKYBRIDGE_MASK_MODE=strict instead aborts the
// row/connection on a masker failure rather than ever forwarding it unmasked.
func logMaskingGuardrails(cfg config.Agent, logger *log.Logger) {
	if logger == nil {
		logger = log.Default()
	}
	presidioOn := cfg.MaskAnalyzeURL != "" && cfg.MaskAnonymizeURL != ""
	overlayOn := len(cfg.PIIOverlay) > 0 || cfg.PIIOverlayURL != ""

	// Half-configured Presidio: one URL without the other disables the remote masker entirely.
	if (cfg.MaskAnalyzeURL != "") != (cfg.MaskAnonymizeURL != "") {
		logger.Printf("skybridge-agent: WARNING: Presidio masking is half-configured " +
			"(set BOTH SKYBRIDGE_MASK_ANALYZE_URL and SKYBRIDGE_MASK_ANONYMIZE_URL); the remote masker is DISABLED")
	}

	switch {
	case !presidioOn && !overlayOn:
		logger.Printf("skybridge-agent: WARNING: no masking configured — result rows are forwarded UNMASKED " +
			"(transparent passthrough). Set SKYBRIDGE_MASK_ANALYZE_URL/SKYBRIDGE_MASK_ANONYMIZE_URL " +
			"and/or SKYBRIDGE_PII_OVERLAY / SKYBRIDGE_PII_OVERLAY_URL.")
	case !presidioOn && overlayOn:
		logger.Printf("skybridge-agent: WARNING: Presidio content masking is not configured " +
			"(SKYBRIDGE_MASK_ANALYZE_URL/SKYBRIDGE_MASK_ANONYMIZE_URL); only exact column-name overlay rules are " +
			"masked — PII in free-text columns, JSON blobs, or unlisted columns will NOT be masked.")
	}

	if presidioOn && cfg.MaskStrict() {
		logger.Printf("skybridge-agent: SKYBRIDGE_MASK_MODE=strict — a Presidio outage or error will abort " +
			"the affected connection instead of forwarding data unmasked.")
	}
}

// MaskingMode returns a short label describing the active masking layers.
func MaskingMode(cfg config.Agent) string {
	mode := ""
	if cfg.MaskAnalyzeURL != "" {
		mode = "remote"
	}
	if len(cfg.PIIOverlay) > 0 || cfg.PIIOverlayURL != "" {
		label := "overlay"
		if cfg.PIIOverlayURL != "" {
			label = "overlay(dynamic)"
		}
		if mode != "" {
			mode += "+" + label
		} else {
			mode = label
		}
	}
	if mode == "" {
		return "none"
	}
	if cfg.MaskAnalyzeURL != "" && cfg.MaskStrict() {
		mode += "(strict)"
	}
	return mode
}

// RunListener serves native clients directly (listener mode).
func RunListener(ctx context.Context, cfg config.Agent, logger *log.Logger) error {
	if logger == nil {
		logger = log.Default()
	}
	if cfg.UpstreamAddr == "" {
		return fmt.Errorf("set SKYBRIDGE_UPSTREAM to the database address (host:port)")
	}
	clientTLS, err := buildClientTLSConfig(cfg, logger)
	if err != nil {
		return err
	}
	engine, err := engineFactory(clientTLS)(cfg.DBType)
	if err != nil {
		return err
	}
	masker, overlay := buildMaskerWithOverlay(cfg)
	startOverlaySync(ctx, cfg, overlay, logger)
	logMaskingGuardrails(cfg, logger)
	resolver := NewHTTPCredentialResolver(cfg)
	upTLS, err := buildUpstreamTLSPolicy(cfg)
	if err != nil {
		return err
	}
	// MySQL negotiates upstream TLS inside its handshake, so it is configured on the engine here;
	// Postgres/Mongo are wrapped at the connection level in the accept loop below.
	engine = upTLS.configureEngine(engine, cfg.DBType, cfg.UpstreamAddr)
	logClientTLSMode(cfg, clientTLS, engine, logger)
	logCredentialMode(cfg, engine, resolver, logger)
	logUpstreamTLSMode(upTLS, []string{cfg.DBType}, logger)

	ln, err := net.Listen("tcp", cfg.ListenAddr)
	if err != nil {
		return fmt.Errorf("listen %s: %w", cfg.ListenAddr, err)
	}
	defer ln.Close()
	go func() { <-ctx.Done(); _ = ln.Close() }()
	logger.Printf("skybridge-agent[listener]: %s proxy %s -> %s (masking: %s)", engine.Name(), cfg.ListenAddr, cfg.UpstreamAddr, MaskingMode(cfg))

	dialer := &net.Dialer{Timeout: dialTimeout}
	for {
		client, err := ln.Accept()
		if err != nil {
			if ctx.Err() != nil {
				return nil
			}
			logger.Printf("accept: %v", err)
			continue
		}
		go func() {
			defer client.Close()
			rawUpstream, err := dialer.DialContext(ctx, "tcp", cfg.UpstreamAddr)
			if err != nil {
				logger.Printf("dial upstream %s: %v", cfg.UpstreamAddr, err)
				return
			}
			upstream := rawUpstream
			if upTLS.enabled() {
				upstream, err = upTLS.startUpstreamTLS(cfg.DBType, rawUpstream, cfg.UpstreamAddr)
				if err != nil {
					_ = rawUpstream.Close()
					logger.Printf("upstream TLS to %s: %v", cfg.UpstreamAddr, err)
					return
				}
			}
			defer upstream.Close()
			sessCtx := ContextWithWireClientIP(ctx, client.RemoteAddr().String())
			// Listener mode has no control-plane session id to tag a transcript with (it never
			// goes through the gateway's SessionStarted call) — replay is tunnel-mode only for now.
			if err := proxyConn(sessCtx, engine, client, upstream, masker, resolver, wire.NoopRecorder{}); err != nil {
				logger.Printf("session ended: %v", err)
			}
		}()
	}
}

// logCredentialMode warns when injection is requested but cannot run, and notes when it is active.
func logCredentialMode(cfg config.Agent, engine wire.Engine, resolver wire.CredentialResolver, logger *log.Logger) {
	if logger == nil {
		logger = log.Default()
	}
	if !cfg.InjectCredentials {
		return
	}
	if resolver == nil {
		logger.Printf("skybridge-agent: WARNING: SKYBRIDGE_INJECT_CREDENTIALS is set but no " +
			"SKYBRIDGE_CREDENTIAL_EXCHANGE_URL is configured; falling back to verbatim auth passthrough.")
		return
	}
	if _, ok := engine.(wire.InjectingEngine); !ok {
		logger.Printf("skybridge-agent: WARNING: credential injection is enabled but the %q engine "+
			"does not support it yet; falling back to verbatim auth passthrough.", engine.Name())
		return
	}
	logger.Printf("skybridge-agent: credential injection ENABLED (clients present a curlix session token; the agent originates upstream auth).")
	if !cfg.ClientTLSConfigured() {
		logger.Printf("skybridge-agent: WARNING: client TLS is OFF, so the session token rides in the " +
			"client's CLEARTEXT password. Run the listener on a trusted/in-network hop, or set " +
			"SKYBRIDGE_CLIENT_TLS_CERT_FILE/_KEY_FILE (or SKYBRIDGE_CLIENT_TLS_SELF_SIGNED for dev).")
	}
}

// logClientTLSMode notes whether the client link is TLS-terminated, and warns when TLS was requested
// for a db type that does not terminate it yet.
func logClientTLSMode(cfg config.Agent, clientTLS *tls.Config, engine wire.Engine, logger *log.Logger) {
	if logger == nil {
		logger = log.Default()
	}
	if !cfg.ClientTLSConfigured() {
		return
	}
	if clientTLS == nil {
		return // builder already logged the reason
	}
	switch engine.Name() {
	case "postgres":
		logger.Printf("skybridge-agent: client TLS termination ENABLED (clients connect with sslmode=require/verify-*).")
	case "mysql":
		logger.Printf("skybridge-agent: client TLS termination ENABLED for MySQL (connect with TLS; for credential " +
			"injection the client must also enable the mysql_clear_password plugin).")
	default:
		logger.Printf("skybridge-agent: WARNING: client TLS is configured but the %q engine does not "+
			"terminate client TLS yet; the client link stays plaintext.", engine.Name())
	}
}

// RunTunnel dials the gateway and serves its streams (tunnel mode), reconnecting on failure.
func RunTunnel(ctx context.Context, cfg config.Agent, deps Deps, logger *log.Logger) error {
	if logger == nil {
		logger = log.Default()
	}
	if cfg.GatewayAddr == "" {
		return fmt.Errorf("set SKYBRIDGE_GATEWAY to the gateway address (host:port)")
	}
	// Build the masker here (rather than letting withDefaults do it) so we can capture the overlay
	// handle and keep it refreshed from the control plane. Respect a test-injected masker.
	if deps.Masker == nil {
		masker, overlay := buildMaskerWithOverlay(cfg)
		deps.Masker = masker
		startOverlaySync(ctx, cfg, overlay, logger)
		logMaskingGuardrails(cfg, logger)
	}
	// Build the engine factory with client-TLS termination (Postgres) unless a test injected one.
	if deps.Engine == nil {
		clientTLS, err := buildClientTLSConfig(cfg, logger)
		if err != nil {
			return err
		}
		deps.Engine = engineFactory(clientTLS)
		if clientTLS != nil {
			logger.Printf("skybridge-agent[tunnel]: client TLS termination ENABLED for Postgres targets.")
		}
	}
	if deps.UpstreamTLS == nil {
		upTLS, err := buildUpstreamTLSPolicy(cfg)
		if err != nil {
			return err
		}
		deps.UpstreamTLS = upTLS
		// Tunnel-mode targets are resolved live by the gateway per connection now, so there is no
		// static db-type list to enumerate here (unlike listener mode's single cfg.DBType).
		logUpstreamTLSMode(upTLS, nil, logger)
	}
	deps = deps.withDefaults(cfg)
	if cfg.InjectCredentials {
		if deps.Resolver != nil {
			logger.Printf("skybridge-agent[tunnel]: credential injection ENABLED for Postgres targets (clients present a curlix session token).")
			if !cfg.ClientTLSConfigured() {
				logger.Printf("skybridge-agent[tunnel]: WARNING: client TLS is OFF; the session token rides in the client's CLEARTEXT password. Set SKYBRIDGE_CLIENT_TLS_* or keep the client link on a trusted hop.")
			}
		} else {
			logger.Printf("skybridge-agent[tunnel]: WARNING: SKYBRIDGE_INJECT_CREDENTIALS set but no SKYBRIDGE_CREDENTIAL_EXCHANGE_URL; using verbatim auth passthrough.")
		}
	}
	dialer := &net.Dialer{Timeout: dialTimeout}
	var wireTLS *tls.Config
	hasPresetCert := len(cfg.WireMtlsClientCertPEM) > 0 && len(cfg.WireMtlsClientKeyPEM) > 0
	if cfg.WireMtlsConfigured() {
		switch {
		case cfg.WireMtlsIamAuthEnabled:
			logger.Printf("skybridge-agent[tunnel]: wire mTLS via AWS IAM auth configured (%s) — will present a client cert instead of the bearer token once enrolled.", cfg.WireMtlsEnrollURL)
		case hasPresetCert:
			logger.Printf("skybridge-agent[tunnel]: wire mTLS configured with a pre-issued client cert — will present it instead of the bearer token.")
		default:
			logger.Printf("skybridge-agent[tunnel]: wire mTLS enrollment configured (%s) — will present a client cert instead of the bearer token once enrolled.", cfg.WireMtlsEnrollURL)
		}
	}

	for ctx.Err() == nil {
		if cfg.WireMtlsIamAuthEnabled {
			material, merr := wiremtls.EnsureMaterialViaIAM(ctx,
				wiremtls.IamEnrollConfig{BaseURL: cfg.WireMtlsEnrollURL, TenantID: cfg.OrgID, AgentID: cfg.AgentID},
				wiremtls.EnrollConfig{
					BaseURL:           cfg.WireMtlsEnrollURL,
					TenantID:          cfg.OrgID,
					AgentID:           cfg.AgentID,
					TrustDomain:       cfg.WireMtlsTrustDomain,
					TLSDir:            cfg.WireMtlsTLSDir,
					CABundlePEM:       cfg.WireMtlsCABundlePEM,
					IdentitySecretARN: cfg.WireMtlsIdentitySecretARN,
				},
			)
			if merr != nil {
				logger.Printf("wire mTLS IAM enroll: %v (retrying)", merr)
				if !sleep(ctx, 3*time.Second) {
					return nil
				}
				continue
			}
			if material != nil {
				tlsCfg, terr := material.ClientTLSConfig()
				if terr != nil {
					logger.Printf("wire mTLS material invalid: %v (retrying)", terr)
					if !sleep(ctx, 3*time.Second) {
						return nil
					}
					continue
				}
				wireTLS = tlsCfg
			}
		} else if hasPresetCert {
			material := &wiremtls.Material{
				CABundlePEM:   cfg.WireMtlsCABundlePEM,
				ClientCertPEM: cfg.WireMtlsClientCertPEM,
				ClientKeyPEM:  cfg.WireMtlsClientKeyPEM,
			}
			tlsCfg, terr := material.ClientTLSConfig()
			if terr != nil {
				logger.Printf("wire mTLS preset cert invalid: %v (retrying)", terr)
				if !sleep(ctx, 3*time.Second) {
					return nil
				}
				continue
			}
			wireTLS = tlsCfg
		} else if cfg.WireMtlsConfigured() {
			material, merr := wiremtls.EnsureMaterial(ctx, wiremtls.EnrollConfig{
				BaseURL:           cfg.WireMtlsEnrollURL,
				TenantID:          cfg.OrgID,
				AgentID:           cfg.AgentID,
				EnrollToken:       cfg.WireMtlsEnrollToken,
				TrustDomain:       cfg.WireMtlsTrustDomain,
				TLSDir:            cfg.WireMtlsTLSDir,
				CABundlePEM:       cfg.WireMtlsCABundlePEM,
				IdentitySecretARN: cfg.WireMtlsIdentitySecretARN,
			})
			if merr != nil {
				logger.Printf("wire mTLS enroll: %v (retrying)", merr)
				if !sleep(ctx, 3*time.Second) {
					return nil
				}
				continue
			}
			if material != nil {
				tlsCfg, terr := material.ClientTLSConfig()
				if terr != nil {
					logger.Printf("wire mTLS material invalid: %v (retrying)", terr)
					if !sleep(ctx, 3*time.Second) {
						return nil
					}
					continue
				}
				wireTLS = tlsCfg
			}
		}

		conn, err := dialer.DialContext(ctx, "tcp", cfg.GatewayAddr)
		if err != nil {
			logger.Printf("dial gateway %s: %v (retrying)", cfg.GatewayAddr, err)
			if !sleep(ctx, 3*time.Second) {
				return nil
			}
			continue
		}
		mode := "bearer-token"
		if wireTLS != nil {
			conn = tls.Client(conn, wireTLS)
			mode = "mTLS"
		}
		logger.Printf("skybridge-agent[tunnel]: connected to gateway %s as %q (%s, masking: %s)", cfg.GatewayAddr, cfg.AgentID, mode, MaskingMode(cfg))
		if err := ServeTunnelConn(ctx, conn, cfg, deps, logger); err != nil && ctx.Err() == nil {
			logger.Printf("tunnel session ended: %v (reconnecting)", err)
		}
		if !sleep(ctx, 2*time.Second) {
			return nil
		}
	}
	return nil
}

// ServeTunnelConn registers over an established gateway connection and serves inbound streams. It is
// separated from RunTunnel so tests can drive it over an in-memory pipe.
func ServeTunnelConn(ctx context.Context, conn net.Conn, cfg config.Agent, deps Deps, logger *log.Logger) error {
	if logger == nil {
		logger = log.Default()
	}
	deps = deps.withDefaults(cfg)
	sess := tunnel.Client(conn)
	defer sess.Close()

	if err := sess.SendControl(tunnel.Control{
		Kind:    tunnel.KindRegister,
		AgentID: cfg.AgentID,
		OrgID:   cfg.OrgID,
		Token:   cfg.Token,
	}); err != nil {
		return err
	}
	ack, err := sess.NextControl()
	if err != nil {
		return err
	}
	if ack.Kind != tunnel.KindRegisterAck || !ack.OK {
		return fmt.Errorf("gateway rejected registration: %s", ack.Error)
	}

	go heartbeatLoop(ctx, sess)
	go func() {
		select {
		case <-ctx.Done():
			sess.Close()
		case <-sess.Closed():
		}
	}()

	for {
		st, err := sess.Accept()
		if err != nil {
			return err
		}
		go serveStream(ctx, st, sess, cfg, deps, logger)
	}
}

func serveStream(ctx context.Context, st *tunnel.Stream, sess *tunnel.Session, cfg config.Agent, deps Deps, logger *log.Logger) {
	defer st.Close()
	meta, err := tunnel.DecodeOpenMeta(st.Meta())
	if err != nil {
		logger.Printf("stream open: bad meta: %v", err)
		return
	}
	if meta.Addr == "" || meta.DBType == "" {
		logger.Printf("stream open: gateway sent no addr/db_type for target %q "+
			"(upgrade the gateway or check its SKYBRIDGE_GW_CONTROL_PLANE_URL)", meta.Target)
		return
	}
	if meta.DBType == "kubernetes" {
		serveK8sStream(ctx, st, meta, cfg, logger)
		return
	}
	engine, err := deps.Engine(meta.DBType)
	if err != nil {
		logger.Printf("stream open: %v", err)
		return
	}
	engine = deps.UpstreamTLS.configureEngine(engine, meta.DBType, meta.Addr)
	rawUpstream, err := deps.Dial(ctx, "tcp", meta.Addr)
	if err != nil {
		logger.Printf("dial upstream %s: %v", meta.Addr, err)
		return
	}
	upstream := rawUpstream
	if deps.UpstreamTLS.enabled() {
		upstream, err = deps.UpstreamTLS.startUpstreamTLS(meta.DBType, rawUpstream, meta.Addr)
		if err != nil {
			_ = rawUpstream.Close()
			logger.Printf("upstream TLS to %s: %v", meta.Addr, err)
			return
		}
	}
	defer upstream.Close()
	// Session replay (hoop.dev parity): the gateway already opened a control-plane session and
	// put its id on OpenMeta (see gateway.go's ServeClient) — build a recorder tagged with it so
	// the wire engine's already-masked traffic gets captured, then flush once the session ends.
	// SessionReplayEnabled gates this independently of session recording itself (a deployment can
	// record byte-count metadata without opting into full transcript capture).
	recorder := newTranscriptRecorder(meta.SessionID, cfg)
	defer flushTranscript(recorder, sess, logger)
	if err := proxyConn(ctx, engine, st, upstream, deps.Masker, deps.Resolver, recorder); err != nil {
		logger.Printf("target %q session ended: %v", meta.Target, err)
	}
}

func heartbeatLoop(ctx context.Context, sess *tunnel.Session) {
	t := time.NewTicker(heartbeatInterval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-sess.Closed():
			return
		case <-t.C:
			if err := sess.SendControl(tunnel.Control{Kind: tunnel.KindHeartbeat}); err != nil {
				return
			}
		}
	}
}

func sleep(ctx context.Context, d time.Duration) bool {
	select {
	case <-ctx.Done():
		return false
	case <-time.After(d):
		return true
	}
}
