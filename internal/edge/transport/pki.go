package transport

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
)

// DefaultTrustDomain is the SPIFFE trust domain placed in the CSR's URI SAN. The CSR SAN is only
// informational — the gateway's CA sets the authoritative identity SAN when it signs — so this value
// does not need to match the gateway and stays vendor-neutral by default.
const DefaultTrustDomain = "skybridge.edge"

// spiffeID builds spiffe://<trust-domain>/tenant/<tenant>/connector/<connector>.
func spiffeID(trustDomain, tenant, connector string) string {
	td := strings.TrimSpace(trustDomain)
	if td == "" {
		td = DefaultTrustDomain
	}
	conn := strings.TrimSpace(connector)
	if conn == "" {
		conn = "edge"
	}
	return fmt.Sprintf("spiffe://%s/tenant/%s/connector/%s", td, strings.TrimSpace(tenant), conn)
}

// generateKeyAndCSR creates an EC P-256 key (PKCS#8 PEM) and a PKCS#10 CSR (PEM) carrying the SPIFFE
// URI SAN. The private key never leaves the edge.
func generateKeyAndCSR(trustDomain, tenant, connector string) (keyPEM, csrPEM []byte, err error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, nil, fmt.Errorf("generate key: %w", err)
	}
	der, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return nil, nil, fmt.Errorf("marshal key: %w", err)
	}
	keyPEM = pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der})

	uri, err := url.Parse(spiffeID(trustDomain, tenant, connector))
	if err != nil {
		return nil, nil, fmt.Errorf("spiffe uri: %w", err)
	}
	cn := strings.TrimSpace(connector)
	if cn == "" {
		cn = "skybridge-edge"
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

// serverTLSConfig trusts the gateway's CA (or system roots when caPEM is empty) with no client cert.
// Used for the Enroll bootstrap call.
func serverTLSConfig(caPEM []byte) (*tls.Config, error) {
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

// mtlsTLSConfig presents the edge's client cert and trusts the gateway CA. Used for Connect.
func mtlsTLSConfig(m *tlsMaterial) (*tls.Config, error) {
	pair, err := tls.X509KeyPair(m.clientCertPEM, m.clientKeyPEM)
	if err != nil {
		return nil, fmt.Errorf("load client keypair: %w", err)
	}
	cfg := &tls.Config{MinVersion: tls.VersionTLS12, Certificates: []tls.Certificate{pair}}
	if len(m.caBundlePEM) > 0 {
		pool := x509.NewCertPool()
		if !pool.AppendCertsFromPEM(m.caBundlePEM) {
			return nil, errors.New("invalid CA bundle PEM")
		}
		cfg.RootCAs = pool
	}
	return cfg, nil
}
