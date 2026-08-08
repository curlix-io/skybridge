package agent

import (
	"context"
	"crypto/tls"
	"log"
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
func serveK8sStream(ctx context.Context, st *tunnel.Stream, meta tunnel.OpenMeta, cfg config.Agent, logger *log.Logger) {
	if logger == nil {
		logger = log.Default()
	}
	if len(cfg.K8sClientTLSCertPEM) == 0 || len(cfg.K8sClientTLSKeyPEM) == 0 {
		logger.Printf("stream open: target %q is a kubernetes proxy but SKYBRIDGE_K8S_CLIENT_TLS_CERT_PEM/_KEY_PEM is not set", meta.Target)
		return
	}
	resolver := NewHTTPK8sCredentialResolver(cfg)
	if resolver == nil {
		logger.Printf("stream open: target %q is a kubernetes proxy but SKYBRIDGE_K8S_CREDENTIAL_EXCHANGE_URL is not set", meta.Target)
		return
	}
	clientCert, err := tls.X509KeyPair(cfg.K8sClientTLSCertPEM, cfg.K8sClientTLSKeyPEM)
	if err != nil {
		logger.Printf("stream open: kubernetes proxy client TLS cert/key: %v", err)
		return
	}
	clientTLS := &tls.Config{Certificates: []tls.Certificate{clientCert}, MinVersion: tls.VersionTLS12}

	dialer := &net.Dialer{Timeout: dialTimeout}
	upstream, err := dialer.DialContext(ctx, "tcp", meta.Addr)
	if err != nil {
		logger.Printf("dial kubernetes API server %s: %v", meta.Addr, err)
		return
	}
	defer upstream.Close()

	engine := k8sapi.New(clientTLS)
	if err := engine.ProxyInject(ctx, st, upstream, resolver, wire.NoopRecorder{}); err != nil {
		logger.Printf("target %q kubernetes proxy session ended: %v", meta.Target, err)
	}
}
