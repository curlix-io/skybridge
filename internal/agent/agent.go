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
func proxyConn(ctx context.Context, engine wire.Engine, client, upstream net.Conn, masker mask.Masker, resolver wire.CredentialResolver) error {
	if resolver != nil {
		if ie, ok := engine.(wire.InjectingEngine); ok {
			return ie.ProxyInject(ctx, client, upstream, masker, resolver)
		}
	}
	return engine.Proxy(ctx, client, upstream, masker)
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
// operator likely intends. The wire proxy is fail-open (a miss forwards the value unchanged), so a
// missing layer silently lets data through — these logs make that explicit at boot.
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
			if err := proxyConn(ctx, engine, client, upstream, masker, resolver); err != nil {
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
	if len(cfg.Targets) == 0 {
		return fmt.Errorf("set SKYBRIDGE_TARGETS to a JSON array of {name,addr,db_type}")
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
		dbTypes := make([]string, 0, len(cfg.Targets))
		for _, t := range cfg.Targets {
			dbTypes = append(dbTypes, t.DBType)
		}
		logUpstreamTLSMode(upTLS, dbTypes, logger)
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

	for ctx.Err() == nil {
		conn, err := dialer.DialContext(ctx, "tcp", cfg.GatewayAddr)
		if err != nil {
			logger.Printf("dial gateway %s: %v (retrying)", cfg.GatewayAddr, err)
			if !sleep(ctx, 3*time.Second) {
				return nil
			}
			continue
		}
		logger.Printf("skybridge-agent[tunnel]: connected to gateway %s as %q (%d targets, masking: %s)", cfg.GatewayAddr, cfg.AgentID, len(cfg.Targets), MaskingMode(cfg))
		if err := ServeTunnelConn(ctx, conn, cfg, deps, logger); err != nil {
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
		Targets: cfg.Targets,
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
		go serveStream(ctx, st, cfg, deps, logger)
	}
}

func serveStream(ctx context.Context, st *tunnel.Stream, cfg config.Agent, deps Deps, logger *log.Logger) {
	defer st.Close()
	meta, err := tunnel.DecodeOpenMeta(st.Meta())
	if err != nil {
		logger.Printf("stream open: bad meta: %v", err)
		return
	}
	target, ok := cfg.TargetByName(meta.Target)
	if !ok {
		logger.Printf("stream open: unknown target %q", meta.Target)
		return
	}
	engine, err := deps.Engine(target.DBType)
	if err != nil {
		logger.Printf("stream open: %v", err)
		return
	}
	engine = deps.UpstreamTLS.configureEngine(engine, target.DBType, target.Addr)
	rawUpstream, err := deps.Dial(ctx, "tcp", target.Addr)
	if err != nil {
		logger.Printf("dial upstream %s: %v", target.Addr, err)
		return
	}
	upstream := rawUpstream
	if deps.UpstreamTLS.enabled() {
		upstream, err = deps.UpstreamTLS.startUpstreamTLS(target.DBType, rawUpstream, target.Addr)
		if err != nil {
			_ = rawUpstream.Close()
			logger.Printf("upstream TLS to %s: %v", target.Addr, err)
			return
		}
	}
	defer upstream.Close()
	if err := proxyConn(ctx, engine, st, upstream, deps.Masker, deps.Resolver); err != nil {
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
