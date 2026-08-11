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
	"log/slog"
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
func buildClientTLSConfig(cfg config.Agent, logger *slog.Logger) (*tls.Config, error) {
	if logger == nil {
		logger = slog.Default()
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
		logger.Warn("using an EPHEMERAL self-signed client TLS cert " +
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

// engineFactory returns an engine selector that builds the Postgres, MySQL and Mongo engines with
// client-TLS termination when clientTLS is non-nil (needed for credential injection, where the
// client sends a session token). orgID scopes mask.Column.ObjectID for path-/table-aware masking
// labels (see internal/pathlabel); MySQL resolves it from its column-definition packets and Mongo
// resolves it by correlating each find/aggregate/getMore request's collection with its reply (see
// internal/wire/mongo package doc). Postgres resolves it too, but only when pgCatalog is non-nil
// (SKYBRIDGE_POSTGRES_CATALOG_DSN configured — see buildPostgresCatalogResolver and REDACTION.md's
// "Postgres table-identity resolution" design notes); pgCatalog is shared across every Postgres
// connection this agent serves so its per-database OID cache persists for the agent's lifetime,
// not just one session.
func engineFactory(clientTLS *tls.Config, orgID string, pgCatalog *postgres.CatalogResolver) func(string) (wire.Engine, error) {
	return func(dbType string) (wire.Engine, error) {
		switch dbType {
		case "postgres", "postgresql":
			var e *postgres.Engine
			if clientTLS != nil {
				e = postgres.NewWithClientTLS(clientTLS)
			} else {
				e = postgres.New()
			}
			if pgCatalog != nil {
				e = e.WithOrgID(orgID).WithCatalogResolver(pgCatalog)
			}
			return e, nil
		case "mysql":
			if clientTLS != nil {
				return mysql.NewWithClientTLS(clientTLS).WithOrgID(orgID), nil
			}
			return mysql.New().WithOrgID(orgID), nil
		case "mongodb", "mongo":
			if clientTLS != nil {
				return mongo.NewWithClientTLS(clientTLS).WithOrgID(orgID), nil
			}
			return mongo.New().WithOrgID(orgID), nil
		default:
			return nil, fmt.Errorf("unsupported db type %q (want postgres|mysql|mongodb)", dbType)
		}
	}
}

// buildPostgresCatalogResolver returns a shared CatalogResolver when cfg.PostgresCatalogDSN is set,
// or nil otherwise (leaving Postgres's ObjectID unresolved, the safe no-op this package has always
// had). A malformed DSN is a startup-time configuration error, not a best-effort fallback — unlike
// the lookups it enables, which degrade silently per-call (see CatalogResolver.Resolve).
func buildPostgresCatalogResolver(cfg config.Agent) (*postgres.CatalogResolver, error) {
	if cfg.PostgresCatalogDSN == "" {
		return nil, nil
	}
	cred, err := postgres.ParseCatalogDSN(cfg.PostgresCatalogDSN)
	if err != nil {
		return nil, fmt.Errorf("SKYBRIDGE_POSTGRES_CATALOG_DSN: %w", err)
	}
	return postgres.NewCatalogResolver(cred), nil
}

// logPostgresCatalogMode notes when Postgres table-identity resolution (PathOverlay support for
// the Postgres wire proxy) is active, mirroring logClientTLSMode/logCredentialMode/
// logUpstreamTLSMode's pattern of surfacing an optional feature's on/off state at startup.
func logPostgresCatalogMode(cfg config.Agent, pgCatalog *postgres.CatalogResolver, logger *slog.Logger) {
	if logger == nil {
		logger = slog.Default()
	}
	if pgCatalog == nil {
		return
	}
	note := ""
	if cfg.PathLabelURL == "" {
		note = " (SKYBRIDGE_PATH_LABEL_URL is not set, so PathOverlay itself is not yet in the masking chain — this only prepares identity resolution for when it is)"
	}
	logger.Info(fmt.Sprintf("Postgres table-identity resolution ENABLED (SKYBRIDGE_POSTGRES_CATALOG_DSN)%s.", note))
}
