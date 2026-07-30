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
	"math/big"
	"time"
)

// ServerConfig builds a tls.Config for the gateway's agent-listen socket: presents serverCertPEM/
// serverKeyPEM and REQUIRES + verifies an agent client cert against caBundlePEM. Callers extract the
// verified agent identity from the peer certificate's SPIFFE SAN (see IdentityFromCert) once the TLS
// handshake completes.
func ServerConfig(serverCertPEM, serverKeyPEM, caBundlePEM []byte) (*tls.Config, error) {
	pair, err := tls.X509KeyPair(serverCertPEM, serverKeyPEM)
	if err != nil {
		return nil, err
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(caBundlePEM) {
		return nil, errors.New("invalid CA bundle PEM")
	}
	return &tls.Config{
		MinVersion:   tls.VersionTLS12,
		Certificates: []tls.Certificate{pair},
		ClientCAs:    pool,
		ClientAuth:   tls.RequireAndVerifyClientCert,
	}, nil
}

// GenerateSelfSignedServerCert mints an ephemeral ECDSA P-256 self-signed cert for the gateway's
// agent-listen socket when no operator-provided server cert is configured (dev only). Client cert
// verification against the wire mTLS CA is what authenticates agents; a production deployment
// should still provide a real server cert (SKYBRIDGE_GW_MTLS_SERVER_CERT_PEM/_KEY_PEM) so the
// agent's TLS handshake actually authenticates the gateway too, not just the reverse.
func GenerateSelfSignedServerCert() (certPEM, keyPEM []byte, err error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, nil, err
	}
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return nil, nil, err
	}
	tmpl := &x509.Certificate{
		SerialNumber:          serial,
		Subject:               pkix.Name{CommonName: "skybridge-gateway"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(825 * 24 * time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		DNSNames:              []string{"localhost", "skybridge-gateway"},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		return nil, nil, err
	}
	keyDER, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return nil, nil, err
	}
	certPEM = pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	keyPEM = pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER})
	return certPEM, keyPEM, nil
}
