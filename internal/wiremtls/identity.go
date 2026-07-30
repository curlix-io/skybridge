// Package wiremtls implements mTLS identity for the Skybridge wire gateway↔agent tunnel (Phase 2,
// docs/design/identity-aware-network-access.md). It replaces the plaintext SKYBRIDGE_GW_TOKEN
// shared-secret check with a per-agent client certificate carrying a SPIFFE URI SAN:
//
//	spiffe://curlix.wire-agent/tenant/<tenant_id>/agent/<agent_id>
//
// The cert is obtained via a one-time-token HTTP enroll bootstrap against the control plane (see
// EnrollHTTP), not gRPC — the wire tunnel is raw TCP with hand-rolled framing (internal/tunnel), so
// this package deliberately does not introduce gRPC into that path. Once enrolled, ListenAgents'
// net.Listener and RunTunnel's dialer are wrapped in tls.Config built from the enrolled material.
package wiremtls

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"fmt"
	"net/url"
	"strings"
	"time"
)

// DefaultTrustDomain is the SPIFFE trust domain placed in the CSR's URI SAN. The CSR SAN is only
// informational — the gateway's CA sets the authoritative identity SAN when it signs.
const DefaultTrustDomain = "curlix.wire-agent"

// SpiffeID builds spiffe://<trust-domain>/tenant/<tenant>/agent/<agent>.
func SpiffeID(trustDomain, tenant, agentID string) string {
	td := strings.TrimSpace(trustDomain)
	if td == "" {
		td = DefaultTrustDomain
	}
	a := strings.TrimSpace(agentID)
	if a == "" {
		a = "agent"
	}
	return fmt.Sprintf("spiffe://%s/tenant/%s/agent/%s", td, strings.TrimSpace(tenant), a)
}

// GenerateKeyAndCSR creates an EC P-256 key (PKCS#8 PEM) and a PKCS#10 CSR (PEM) carrying the SPIFFE
// URI SAN. The private key never leaves the agent.
func GenerateKeyAndCSR(trustDomain, tenant, agentID string) (keyPEM, csrPEM []byte, err error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, nil, fmt.Errorf("generate key: %w", err)
	}
	der, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return nil, nil, fmt.Errorf("marshal key: %w", err)
	}
	keyPEM = pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der})

	uri, err := url.Parse(SpiffeID(trustDomain, tenant, agentID))
	if err != nil {
		return nil, nil, fmt.Errorf("spiffe uri: %w", err)
	}
	cn := strings.TrimSpace(agentID)
	if cn == "" {
		cn = "curlix-wire-agent"
	}
	tmpl := &x509.CertificateRequest{
		Subject:            pkix.Name{CommonName: cn},
		URIs:               []*url.URL{uri},
		SignatureAlgorithm: x509.ECDSAWithSHA256,
	}
	csrDER, err := x509.CreateCertificateRequest(rand.Reader, tmpl, key)
	if err != nil {
		return nil, nil, fmt.Errorf("create csr: %w", err)
	}
	csrPEM = pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: csrDER})
	return keyPEM, csrPEM, nil
}

// ServerTLSConfig trusts the CA bundle (or system roots when caPEM is empty), presenting no client
// cert. Used for the Enroll bootstrap call (plain HTTPS, no client cert required yet).
func ServerTLSConfig(caPEM []byte) (*tls.Config, error) {
	cfg := &tls.Config{MinVersion: tls.VersionTLS12}
	if len(caPEM) > 0 {
		pool := x509.NewCertPool()
		if !pool.AppendCertsFromPEM(caPEM) {
			return nil, errors.New("invalid CA bundle PEM")
		}
		cfg.RootCAs = pool
	}
	return cfg, nil
}

// Material is the wire agent's mTLS identity: its client cert/key plus the CA bundle it (and the
// gateway) trust. A nil *Material means "no mTLS configured" — callers fall back to the legacy
// SKYBRIDGE_GW_TOKEN shared-secret path.
type Material struct {
	CABundlePEM   []byte
	ClientCertPEM []byte
	ClientKeyPEM  []byte
}

// ClientTLSConfig presents the agent's client cert and trusts the CA bundle. Used by RunTunnel's
// dialer to mTLS-wrap the gateway connection.
//
// The gateway's own server cert (GenerateSelfSignedServerCert in server.go) is ephemeral and
// self-signed unless an operator configures SKYBRIDGE_GW_MTLS_SERVER_CERT_PEM/_KEY — CABundlePEM
// here is the CA that signs *client* (agent) certs, an unrelated trust chain that can never verify
// that server cert. So server-cert verification is skipped by default (mirrors the "only
// authenticates the reverse" gap noted on ServerConfig); once a real, CA-chained server cert is
// configured on the gateway, set cfg.RootCAs from that server CA to turn verification back on.
func (m *Material) ClientTLSConfig() (*tls.Config, error) {
	pair, err := tls.X509KeyPair(m.ClientCertPEM, m.ClientKeyPEM)
	if err != nil {
		return nil, fmt.Errorf("load client keypair: %w", err)
	}
	return &tls.Config{
		MinVersion:         tls.VersionTLS12,
		Certificates:       []tls.Certificate{pair},
		InsecureSkipVerify: true, //nolint:gosec // client cert auth is the load-bearing check; see comment above
	}, nil
}

// CertValid reports whether cert_pem is unexpired with at least `skew` of validity remaining.
func CertValid(certPEM []byte, skew time.Duration) bool {
	block, _ := pem.Decode(certPEM)
	if block == nil {
		return false
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return false
	}
	return time.Now().Add(skew).Before(cert.NotAfter)
}

// IdentityFromCert extracts (tenant_id, agent_id) from a verified peer certificate's SPIFFE URI SAN.
func IdentityFromCert(cert *x509.Certificate) (tenant, agentID string, ok bool) {
	for _, u := range cert.URIs {
		t, a, parsed := ParseSpiffeID(u.String())
		if parsed {
			return t, a, true
		}
	}
	return "", "", false
}

// ParseSpiffeID parses spiffe://<trust-domain>/tenant/<tenant>/agent/<agent>.
func ParseSpiffeID(uri string) (tenant, agentID string, ok bool) {
	u, err := url.Parse(uri)
	if err != nil || u.Scheme != "spiffe" {
		return "", "", false
	}
	segs := strings.Split(strings.Trim(u.Path, "/"), "/")
	if len(segs) != 4 || segs[0] != "tenant" || segs[2] != "agent" {
		return "", "", false
	}
	if segs[1] == "" || segs[3] == "" {
		return "", "", false
	}
	return segs[1], segs[3], true
}
