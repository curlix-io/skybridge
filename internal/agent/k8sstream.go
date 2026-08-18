package agent

import (
	"context"
	"crypto/tls"
	"fmt"
	"log/slog"
	"net"

	"github.com/curlix-io/skybridge/internal/config"
	"github.com/curlix-io/skybridge/internal/tunnel"
	"github.com/curlix-io/skybridge/internal/wire"
	"github.com/curlix-io/skybridge/internal/wire/k8sapi"
)

// serveK8sStream serves one gateway-relayed Kubernetes API proxy stream. Separate from serveStream's
// generic DB-engine dispatch because Kubernetes auth is a bearer token presented per-request rather
// than a one-time login handshake (see k8sapi's package doc) — deps.Engine/deps.Resolver's
// per-connection shapes don't fit, so this builds the k8sapi engine and resolver directly from cfg.
func serveK8sStream(ctx context.Context, st *tunnel.Stream, meta tunnel.OpenMeta, cfg config.Agent, logger *slog.Logger) {
	if logger == nil {
		logger = slog.Default()
	}
	clientTLS, err := k8sClientTLSConfig(cfg)
	if err != nil {
		logger.Error(fmt.Sprintf("stream open: target %q is a kubernetes proxy: %v", meta.Target, err))
		return
	}
	resolver := NewHTTPK8sCredentialResolver(cfg)
	if resolver == nil {
		logger.Error(fmt.Sprintf("stream open: target %q is a kubernetes proxy but SKYBRIDGE_K8S_CREDENTIAL_EXCHANGE_URL is not set", meta.Target))
		return
	}

	dialer := &net.Dialer{Timeout: dialTimeout}
	upstream, err := dialer.DialContext(ctx, "tcp", meta.Addr)
	if err != nil {
		logger.Error(fmt.Sprintf("dial kubernetes API server %s: %v", meta.Addr, err))
		return
	}
	defer upstream.Close()

	engine := k8sapi.New(clientTLS)
	if err := engine.ProxyInject(ctx, st, upstream, resolver, wire.NoopRecorder{}); err != nil {
		logger.Info(fmt.Sprintf("target %q kubernetes proxy session ended: %v", meta.Target, err))
	}
}

// k8sClientTLSConfig builds the client-facing TLS config shared by serveK8sStream (tunnel mode)
// and RunK8sAPIListener (standalone in-cluster mode) — same cert/key env vars, same validation.
func k8sClientTLSConfig(cfg config.Agent) (*tls.Config, error) {
	if len(cfg.K8sClientTLSCertPEM) == 0 || len(cfg.K8sClientTLSKeyPEM) == 0 {
		return nil, fmt.Errorf("SKYBRIDGE_K8S_CLIENT_TLS_CERT_PEM/_KEY_PEM is not set")
	}
	cert, err := tls.X509KeyPair(cfg.K8sClientTLSCertPEM, cfg.K8sClientTLSKeyPEM)
	if err != nil {
		return nil, fmt.Errorf("client TLS cert/key: %w", err)
	}
	return &tls.Config{Certificates: []tls.Certificate{cert}, MinVersion: tls.VersionTLS12}, nil
}

// RunK8sAPIListener binds cfg.K8sAPIListenAddr and serves kubectl directly against
// cfg.K8sAPIUpstreamAddr — the governed-access-parity path (docs/design/kubernetes-access-broker.md
// §11.1): when this agent runs *inside* the cluster it grants access to, it serves that cluster's
// API directly instead of tunneling out to a shared gateway and back in. Blocks until ctx is
// cancelled or the listener fails. Independent of WireProxy.Mode/RunTunnel/RunListener — those are
// for the native DB wire proxy only.
func RunK8sAPIListener(ctx context.Context, cfg config.Agent, logger *slog.Logger) error {
	if logger == nil {
		logger = slog.Default()
	}
	clientTLS, err := k8sClientTLSConfig(cfg)
	if err != nil {
		return fmt.Errorf("k8s API listener: %w", err)
	}
	resolver := NewHTTPK8sCredentialResolver(cfg)
	if resolver == nil {
		return fmt.Errorf("k8s API listener: SKYBRIDGE_K8S_CREDENTIAL_EXCHANGE_URL is not set")
	}
	upstreamAddr := cfg.K8sAPIUpstreamAddr
	if upstreamAddr == "" {
		upstreamAddr = "kubernetes.default.svc:443"
	}

	ln, err := net.Listen("tcp", cfg.K8sAPIListenAddr)
	if err != nil {
		return fmt.Errorf("k8s API listener: %w", err)
	}
	logger.Info(fmt.Sprintf("k8s API listener %s -> %s (in-cluster, no gateway hop)", cfg.K8sAPIListenAddr, upstreamAddr))
	go func() {
		<-ctx.Done()
		_ = ln.Close()
	}()

	dialer := &net.Dialer{Timeout: dialTimeout}
	for {
		client, err := ln.Accept()
		if err != nil {
			if ctx.Err() != nil {
				return nil
			}
			return err
		}
		go func() {
			defer client.Close()
			upstream, err := dialer.DialContext(ctx, "tcp", upstreamAddr)
			if err != nil {
				logger.Error(fmt.Sprintf("dial kubernetes API server %s: %v", upstreamAddr, err))
				return
			}
			defer upstream.Close()
			engine := k8sapi.New(clientTLS)
			if err := engine.ProxyInject(ctx, client, upstream, resolver, wire.NoopRecorder{}); err != nil {
				logger.Info(fmt.Sprintf("k8s API proxy session ended: %v", err))
			}
		}()
	}
}
