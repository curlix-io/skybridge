package agent

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"log"
	"math/big"
	"time"

	"github.com/curlix-io/skybridge/internal/config"
	"github.com/curlix-io/skybridge/internal/wire"
	"github.com/curlix-io/skybridge/internal/wire/mongo"
	"github.com/curlix-io/skybridge/internal/wire/mysql"
	"github.com/curlix-io/skybridge/internal/wire/postgres"
)

// buildClientTLSConfig assembles the TLS config used to terminate native-client TLS. It returns
// (nil, nil) when client TLS is not configured (the proxy then declines SSL, as before). A provided
// cert+key wins; otherwise SKYBRIDGE_CLIENT_TLS_SELF_SIGNED generates an ephemeral cert for dev.
func buildClientTLSConfig(cfg config.Agent, logger *log.Logger) (*tls.Config, error) {
	if logger == nil {
		logger = log.Default()
	}
	if len(cfg.ClientTLSCertPEM) > 0 && len(cfg.ClientTLSKeyPEM) > 0 {
		cert, err := tls.X509KeyPair(cfg.ClientTLSCertPEM, cfg.ClientTLSKeyPEM)
		if err != nil {
			return nil, fmt.Errorf("client TLS: bad cert/key pair: %w", err)
		}
		return &tls.Config{Certificates: []tls.Certificate{cert}, MinVersion: tls.VersionTLS12}, nil
	}
	if cfg.ClientTLSSelfSigned {
		cert, err := generateSelfSignedCert()
		if err != nil {
			return nil, fmt.Errorf("client TLS: self-signed cert: %w", err)
		}
		logger.Printf("skybridge-agent: WARNING: using an EPHEMERAL self-signed client TLS cert " +
			"(SKYBRIDGE_CLIENT_TLS_SELF_SIGNED). Clients must connect with sslmode=require (no verify). " +
			"Provide SKYBRIDGE_CLIENT_TLS_CERT_FILE/_KEY_FILE for a trusted cert in production.")
		return &tls.Config{Certificates: []tls.Certificate{cert}, MinVersion: tls.VersionTLS12}, nil
	}
	return nil, nil
}

// generateSelfSignedCert mints a short-lived in-memory ECDSA P-256 self-signed certificate suitable
// for local/dev TLS termination (clients use sslmode=require, which does not verify the chain).
func generateSelfSignedCert() (tls.Certificate, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return tls.Certificate{}, err
	}
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return tls.Certificate{}, err
	}
	tmpl := &x509.Certificate{
		SerialNumber:          serial,
		Subject:               pkix.Name{CommonName: "skybridge-agent"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(365 * 24 * time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		DNSNames:              []string{"localhost", "skybridge-agent"},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		return tls.Certificate{}, err
	}
	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		return tls.Certificate{}, err
	}
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})
	return tls.X509KeyPair(certPEM, keyPEM)
}

// engineFactory returns an engine selector that builds the Postgres and MySQL engines with client-TLS
// termination when clientTLS is non-nil (needed for credential injection, where the client sends a
// session token). Mongo does not yet terminate client TLS.
func engineFactory(clientTLS *tls.Config) func(string) (wire.Engine, error) {
	return func(dbType string) (wire.Engine, error) {
		switch dbType {
		case "postgres", "postgresql":
			if clientTLS != nil {
				return postgres.NewWithClientTLS(clientTLS), nil
			}
			return postgres.New(), nil
		case "mysql":
			if clientTLS != nil {
				return mysql.NewWithClientTLS(clientTLS), nil
			}
			return mysql.New(), nil
		case "mongodb", "mongo":
			return mongo.New(), nil
		default:
			return nil, fmt.Errorf("unsupported db type %q (want postgres|mysql|mongodb)", dbType)
		}
	}
}
