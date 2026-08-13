package main

import (
	"context"
	"crypto/tls"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"net"
	"os"
	"os/signal"
	"syscall"

	"github.com/curlix-io/skybridge/internal/config"
	"github.com/curlix-io/skybridge/internal/gateway"
	skylog "github.com/curlix-io/skybridge/internal/log"
	"github.com/curlix-io/skybridge/internal/wiremtls"
)

// gatewayHelpText covers the SKYBRIDGE_GW_* env vars most operators need. It is intentionally a
// curated subset, not the exhaustive list — see internal/config/config.go's Gateway struct for
// wire-mTLS, control-plane, and rate-limit options not covered here.
const gatewayHelpText = `skybridge gateway — relay gateway: agent endpoint + client listeners.

All configuration is via SKYBRIDGE_GW_* (plus SKYBRIDGE_LOG_LEVEL) environment variables (no other
flags). Common ones:

  Agent endpoint (edges/agents dial in here to register)
    SKYBRIDGE_GW_AGENT_LISTEN     agent listen address (default :8010)
    SKYBRIDGE_GW_MTLS_CA_BUNDLE_PEM   CA bundle for verifying agent client certs (required — the
                                      agent listener refuses to start without it; there is no
                                      bearer-token registration mode)

  Client listeners (native db clients connect here; relayed to a registered agent)
    SKYBRIDGE_GW_CLIENTS          JSON [{"addr":":15432","org_id":"...","target":"postgres"},...]
                                   — a "no agent registered for target" warning at relay time means
                                   nothing has dialed in and registered for this addr's org_id+target
                                   yet (see "skybridge agent"/"skybridge edge --help"'s SKYBRIDGE_UPSTREAM)

  Control plane (session recording, wire-IP admission, live target resolution)
    SKYBRIDGE_GW_CONTROL_PLANE_URL    base URL; unset fails closed for all client connections
    SKYBRIDGE_GW_CONTROL_PLANE_TOKEN  bearer token for the above
    SKYBRIDGE_GW_REQUIRE_ORG_ID       require org_id on every agent registration (default: on when
                                       SKYBRIDGE_GW_CONTROL_PLANE_URL is set)

  Rate limits
    SKYBRIDGE_GW_CLIENT_CONN_PER_MIN         per-client-IP new connections/min
    SKYBRIDGE_GW_ORG_CONN_PER_MIN            per-org new connections/min
    SKYBRIDGE_GW_ORG_MAX_CONCURRENT_CLIENTS  per-org standing connection ceiling (default: 1000
                                              when SKYBRIDGE_GW_CONTROL_PLANE_URL is set, else
                                              unlimited) — bounds the total, not just the rate
    SKYBRIDGE_GW_AGENT_CONN_PER_MIN          per-client-IP agent *registration* attempts/min
                                              (default: unlimited) — separate from the client
                                              limits above; throttles probing the bearer token

Exhaustive list, including wire-mTLS options: internal/config/config.go (Gateway struct).
`

func gatewayFatal(logger *slog.Logger, msg string) {
	logger.Error(msg)
	os.Exit(1)
}

func runGateway(args []string) {
	fs := flag.NewFlagSet("gateway", flag.ExitOnError)
	help := false
	fs.BoolVar(&help, "help", false, "print SKYBRIDGE_GW_* configuration options and exit")
	fs.BoolVar(&help, "h", false, "alias for -help")
	fs.Parse(args)
	if help {
		fmt.Print(gatewayHelpText)
		return
	}

	cfg := config.LoadGateway()
	logger := skylog.New(os.Stderr, "skybridge-gateway", skylog.ParseLevel(cfg.LogLevel))

	gw := gateway.New(logger)
	gw.SetRequireOrgID(cfg.RequireOrgID)
	if lim := gateway.NewConnRateLimiter(cfg.ClientConnPerMin, cfg.OrgConnPerMin); lim != nil {
		gw.SetConnRateLimiter(lim)
		logger.Info(fmt.Sprintf("client conn limits ip=%d/min org=%d/min", cfg.ClientConnPerMin, cfg.OrgConnPerMin))
	}
	if lim := gateway.NewOrgConnLimiter(cfg.OrgMaxConcurrentClients); lim != nil {
		gw.SetOrgConnLimiter(lim)
		logger.Info(fmt.Sprintf("org concurrent connection ceiling=%d", cfg.OrgMaxConcurrentClients))
	}
	if lim := gateway.NewConnRateLimiter(cfg.AgentConnPerMin, 0); lim != nil {
		gw.SetAgentConnLimiter(lim)
		logger.Info(fmt.Sprintf("agent registration attempt limit=%d/min per client IP", cfg.AgentConnPerMin))
	}
	if cfg.ControlPlaneURL != "" {
		gw.SetStore(gateway.NewHTTPStore(cfg.ControlPlaneURL, cfg.SessionPath, cfg.ControlPlaneToken))
		gw.SetWireAdmitter(gateway.NewHTTPWireAdmitter(cfg.ControlPlaneURL, cfg.WireAdmitPath, cfg.ControlPlaneToken))
		gw.SetTargetResolver(gateway.NewHTTPTargetResolver(cfg.ControlPlaneURL, cfg.WireTargetPath, cfg.ControlPlaneToken))
		logger.Info(fmt.Sprintf("session recording -> %s%s", cfg.ControlPlaneURL, cfg.SessionPath))
		logger.Info(fmt.Sprintf("wire IP admission -> %s%s", cfg.ControlPlaneURL, cfg.WireAdmitPath))
		logger.Info(fmt.Sprintf("wire target resolution -> %s%s", cfg.ControlPlaneURL, cfg.WireTargetPath))
	} else {
		logger.Warn("no SKYBRIDGE_GW_CONTROL_PLANE_URL — target resolution will fail closed for all client connections")
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	errs := make(chan error, 1+len(cfg.Clients))

	// Agent registration requires a verified mTLS client certificate unconditionally — there is no
	// bearer-token fallback (see internal/gateway/gateway.go's ServeAgent). Refuse to start rather
	// than run an agent listener nothing can ever successfully register against.
	if !cfg.WireMtlsConfigured() {
		gatewayFatal(logger, "SKYBRIDGE_GW_MTLS_CA_BUNDLE_PEM is required — the agent listener has no bearer-token mode")
	}
	agentLn, err := net.Listen("tcp", cfg.AgentListen)
	if err != nil {
		gatewayFatal(logger, err.Error())
	}
	serverCert, serverKey := cfg.WireMtlsServerCert, cfg.WireMtlsServerKey
	if len(serverCert) == 0 || len(serverKey) == 0 {
		var genErr error
		serverCert, serverKey, genErr = wiremtls.GenerateSelfSignedServerCert()
		if genErr != nil {
			gatewayFatal(logger, fmt.Sprintf("generating self-signed wire mTLS server cert: %v", genErr))
		}
		logger.Warn("using an EPHEMERAL self-signed wire mTLS server cert " +
			"(no SKYBRIDGE_GW_MTLS_SERVER_CERT_PEM/_KEY_PEM). Client cert verification still authenticates " +
			"agents; provide a real server cert in production so agents can verify the gateway too.")
	}
	tlsCfg, tlsErr := wiremtls.ServerConfig(serverCert, serverKey, cfg.WireMtlsCABundlePEM)
	if tlsErr != nil {
		gatewayFatal(logger, fmt.Sprintf("wire mTLS server config: %v", tlsErr))
	}
	agentLn = tls.NewListener(agentLn, tlsCfg)
	logger.Info(fmt.Sprintf("agent endpoint %s (mTLS: agent client certs required)", cfg.AgentListen))
	go func() { errs <- gw.ListenAgents(ctx, agentLn) }()

	for _, cl := range cfg.Clients {
		cl := cl
		if cl.Addr == "" || cl.Target == "" || cl.OrgID == "" {
			gatewayFatal(logger, fmt.Sprintf("client listener missing addr/org_id/target: %+v", cl))
		}
		ln, err := net.Listen("tcp", cl.Addr)
		if err != nil {
			gatewayFatal(logger, err.Error())
		}
		if cfg.ClientProxyProtocol {
			ln = gateway.WrapProxyProtocol(ln, 0)
			logger.Info(fmt.Sprintf("client listener %s expects PROXY protocol (NLB client-IP passthrough)", cl.Addr))
		}
		logger.Info(fmt.Sprintf("client listener %s -> org %q target %q", cl.Addr, cl.OrgID, cl.Target))
		go func() {
			errs <- gw.ListenClients(ctx, ln, cl.OrgID, cl.Target)
		}()
	}

	if len(cfg.Clients) == 0 {
		logger.Warn("no SKYBRIDGE_GW_CLIENTS configured")
	}

	select {
	case <-ctx.Done():
	case err := <-errs:
		if err != nil && !errors.Is(err, net.ErrClosed) && ctx.Err() == nil {
			gatewayFatal(logger, err.Error())
		}
	}
}
