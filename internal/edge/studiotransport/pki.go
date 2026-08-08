//go:build querystudio

package studiotransport

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
)

func generateKeyAndCSR(trustDomain, tenant, agent string) (keyPEM, csrPEM []byte, err error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, nil, fmt.Errorf("generate key: %w", err)
	}
	der, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return nil, nil, fmt.Errorf("marshal key: %w", err)
	}
	keyPEM = pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der})

	uri, err := url.Parse(spiffeID(trustDomain, tenant, agent))
	if err != nil {
		return nil, nil, fmt.Errorf("spiffe uri: %w", err)
	}
	cn := agent
	if cn == "" {
		cn = "studio-agent"
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
