package main

import (
	"context"
	"crypto/tls"
	"errors"
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

func fatal(logger *slog.Logger, msg string) {
	logger.Error(msg)
	os.Exit(1)
}

func main() {
	cfg := config.LoadGateway()
	logger := skylog.New(os.Stderr, "skybridge-gateway", skylog.ParseLevel(cfg.LogLevel))

	gw := gateway.New(cfg.AuthToken, logger)
	gw.SetRequireOrgID(cfg.RequireOrgID)
	if lim := gateway.NewConnRateLimiter(cfg.ClientConnPerMin, cfg.OrgConnPerMin); lim != nil {
		gw.SetConnRateLimiter(lim)
		logger.Info(fmt.Sprintf("client conn limits ip=%d/min org=%d/min", cfg.ClientConnPerMin, cfg.OrgConnPerMin))
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

	agentLn, err := net.Listen("tcp", cfg.AgentListen)
	if err != nil {
		fatal(logger, err.Error())
	}
	if cfg.WireMtlsConfigured() {
		serverCert, serverKey := cfg.WireMtlsServerCert, cfg.WireMtlsServerKey
		if len(serverCert) == 0 || len(serverKey) == 0 {
			var genErr error
			serverCert, serverKey, genErr = wiremtls.GenerateSelfSignedServerCert()
			if genErr != nil {
				fatal(logger, fmt.Sprintf("generating self-signed wire mTLS server cert: %v", genErr))
			}
			logger.Warn("using an EPHEMERAL self-signed wire mTLS server cert " +
				"(no SKYBRIDGE_GW_MTLS_SERVER_CERT_PEM/_KEY_PEM). Client cert verification still authenticates " +
				"agents; provide a real server cert in production so agents can verify the gateway too.")
		}
		tlsCfg, tlsErr := wiremtls.ServerConfig(serverCert, serverKey, cfg.WireMtlsCABundlePEM)
		if tlsErr != nil {
			fatal(logger, fmt.Sprintf("wire mTLS server config: %v", tlsErr))
		}
		agentLn = tls.NewListener(agentLn, tlsCfg)
		logger.Info(fmt.Sprintf("agent endpoint %s (mTLS: agent client certs required)", cfg.AgentListen))
	} else {
		logger.Info(fmt.Sprintf("agent endpoint %s (bearer-token mode — no SKYBRIDGE_GW_MTLS_CA_BUNDLE_PEM configured)", cfg.AgentListen))
	}
	go func() { errs <- gw.ListenAgents(ctx, agentLn) }()

	for _, cl := range cfg.Clients {
		cl := cl
		if cl.Addr == "" || cl.Target == "" || cl.OrgID == "" {
			fatal(logger, fmt.Sprintf("client listener missing addr/org_id/target: %+v", cl))
		}
		ln, err := net.Listen("tcp", cl.Addr)
		if err != nil {
			fatal(logger, err.Error())
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
			fatal(logger, err.Error())
		}
	}
}
