package agent

import (
	"context"
	"crypto/tls"
	"fmt"
	"log/slog"
	"net"

	"github.com/curlix-io/skybridge/internal/config"
	"github.com/curlix-io/skybridge/internal/tunnel"
	"github.com/curlix-io/skybridge/internal/wire/k8sapi"
)

// serveK8sStream serves one gateway-relayed Kubernetes API proxy stream. Separate from serveStream's
// generic DB-engine dispatch because Kubernetes auth is a bearer token presented per-request rather
// than a one-time login handshake (see k8sapi's package doc) — deps.Engine/deps.Resolver's
// per-connection shapes don't fit, so this builds the k8sapi engine and resolver directly from cfg.
func serveK8sStream(ctx context.Context, st *tunnel.Stream, sess *tunnel.Session, meta tunnel.OpenMeta, cfg config.Agent, logger *slog.Logger) {
	if logger == nil {
		logger = slog.Default()
	}
	// k8sAPIListenerClientTLS, not the bare k8sClientTLSConfig it wraps -- despite the name, it
	// covers both the standalone in-cluster listener (RunK8sAPIListener) AND this tunnel-mode
	// stream path: an operator-provided cert/key wins either way, and SKYBRIDGE_K8S_CLIENT_TLS_SELF_SIGNED
	// falls back to a self-generated cert for deployments (e.g. a Helm install with wireProxy
	// tunnel mode but k8sApi.enabled=false) that have no other way to provision one. Before this
	// fix, a tunnel-mode "kubernetes" target with only SELF_SIGNED set still hard-failed with
	// "SKYBRIDGE_K8S_CLIENT_TLS_CERT_PEM/_KEY_PEM is not set" -- the self-signed fallback only ever
	// ran for the standalone listener.
	clientTLS, err := k8sAPIListenerClientTLS(ctx, cfg, logger)
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

	// The gateway already opened a control-plane session and put its id on OpenMeta (same as the
	// DB-engine path in serveStream) — this was previously discarded in favor of wire.NoopRecorder{}
	// even though the session id was already in scope (docs/design/kubernetes-access-broker.md
	// §11.5's audit finding). Fixed: reuse the same tunnel-mode transcript recorder DB sessions get.
	recorder := newTranscriptRecorder(meta.SessionID, cfg)
	defer flushTranscript(recorder, sess, logger)
	engine := k8sapi.New(clientTLS)
	if err := engine.ProxyInject(ctx, st, upstream, resolver, recorder); err != nil {
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

// k8sAPIListenerClientTLS resolves the standalone listener's client-facing TLS: an operator-provided
// cert/key wins (k8sClientTLSConfig, unchanged); otherwise, when K8sClientTLSSelfSigned is set, the
// agent generates (or recovers a previously persisted) self-signed cert itself — the
// CloudFormation/ECS parity path (docs/design/kubernetes-access-broker.md §11.7) that has no
// Helm-style install-time templating to hand one to the container via env vars. Reports the
// resulting cert to the control plane once (best-effort, see certreport.go) so an admin doesn't have
// to manually paste it into the Connectivity panel.
func k8sAPIListenerClientTLS(ctx context.Context, cfg config.Agent, logger *slog.Logger) (*tls.Config, error) {
	if tlsCfg, err := k8sClientTLSConfig(cfg); err == nil {
		return tlsCfg, nil
	} else if !cfg.K8sClientTLSSelfSigned {
		return nil, err
	}
	certPEM, keyPEM, err := ensureSelfSignedCert(ctx, "/var/lib/skybridge/k8sapi-tls", cfg.K8sClientTLSSecretARN)
	if err != nil {
		return nil, fmt.Errorf("self-signed k8s API listener cert: %w", err)
	}
	cert, err := tlsCertificateFromPEM(certPEM, keyPEM)
	if err != nil {
		return nil, fmt.Errorf("self-signed k8s API listener cert: %w", err)
	}
	logger.Warn("using a SELF-SIGNED k8s API listener cert (SKYBRIDGE_K8S_CLIENT_TLS_SELF_SIGNED). " +
		"Register it with an admin (Administration -> Connectivity) for real client-side verification, " +
		"or provide SKYBRIDGE_K8S_CLIENT_TLS_CERT_PEM/_KEY_PEM for a cert you already trust.")
	go reportListenerCert(ctx, cfg, "kubernetes", certPEM, logger)
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
	clientTLS, err := k8sAPIListenerClientTLS(ctx, cfg, logger)
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
			recorder := newHTTPTranscriptRecorder(cfg, "kubernetes")
			defer flushHTTPTranscript(ctx, recorder, logger)
			if err := engine.ProxyInject(ctx, client, upstream, resolver, recorder); err != nil {
				logger.Info(fmt.Sprintf("k8s API proxy session ended: %v", err))
			}
		}()
	}
}
