package transport

import (
	"context"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"

	"github.com/curlix-io/skybridge/internal/certstore"
	"github.com/curlix-io/skybridge/internal/edgeiam"
	connectorv1 "github.com/curlix-io/skybridge/internal/genpb/curlix/connector/v1"
	"github.com/curlix-io/skybridge/internal/spire"
)

// DefaultIamEnrollTokenPath is used when Config.IamEnrollURL is set but no override path is given
// (there is currently no per-call override — every connector deployment hits the same path).
const DefaultIamEnrollTokenPath = "/api/v1/skybridge/enrollments-iam"

// tlsMaterial is the edge's identity: either mTLS (cert/key + CA bundle) or SPIFFE JWT-SVID bearer token.
// A nil *tlsMaterial means "bearer-token mode" (no CA configured).
// When svid is set, it's used as a bearer token; cert fields are ignored.
type tlsMaterial struct {
	caBundlePEM   []byte
	clientCertPEM []byte
	clientKeyPEM  []byte

	// SPIFFE JWT-SVID bearer token (alternative to mTLS certs).
	svid      string
	expiresAt int64 // Unix timestamp when SVID expires
}

// certRenewSkew is how far ahead of expiry a cert is considered too stale to reuse (re-enroll).
const certRenewSkew = time.Hour

// ensureTLSMaterial loads valid identity material (mTLS cert or SPIFFE JWT-SVID) from the identity store,
// enrolling via the gateway if necessary. Returns (nil, nil) when no CA is configured and no SPIRE
// is available, meaning the caller should use bearer mode.
func (c *Client) ensureTLSMaterial(ctx context.Context) (*tlsMaterial, error) {
	if c.cfg.ForceBearer {
		// SKYBRIDGE_CONNECTOR_KEY configured: intentionally stateless bearer-only mode. Never touch
		// certstore (no disk read/write, no Secrets Manager call) even if CABundlePEM/TLSDir are
		// also set — the reusable key is presented fresh via Token on every call instead.
		return nil, nil
	}

	// Try to load SVID from SPIRE if configured.
	if c.cfg.SpireSocketPath != "" {
		mat, err := c.loadSVIDIfAvailable(ctx)
		if err == nil && mat != nil {
			return mat, nil
		}
		if err != nil {
			c.logger.Debug(fmt.Sprintf("failed to load SVID: %v (falling back to mTLS)", err))
		}
	}

	ca := c.cfg.CABundlePEM
	if len(ca) == 0 && c.cfg.TLSDir == "" {
		return nil, nil // no mTLS configured at all -> bearer
	}

	store := certstore.FromEnv(c.tlsDir(), c.cfg.IdentitySecretARN)
	stored, err := store.Load(ctx)
	if err != nil {
		return nil, err
	}

	pickCA := func() []byte {
		if stored != nil && len(stored.CABundlePEM) > 0 {
			return stored.CABundlePEM
		}
		return ca
	}

	if stored != nil && certValid(stored.ClientCertPEM, certRenewSkew) {
		return &tlsMaterial{caBundlePEM: pickCA(), clientCertPEM: stored.ClientCertPEM, clientKeyPEM: stored.ClientKeyPEM}, nil
	}

	if len(ca) == 0 {
		return nil, nil // no CA -> bearer (stored material may be stale/untrusted)
	}

	enrollToken := c.cfg.EnrollToken
	if enrollToken == "" && c.cfg.IamAuthEnabled {
		// No human-minted token needed: presign the edge's own ambient AWS identity (an ECS task
		// role, in production) and exchange it for a fresh, short-lived enroll token. Unlike a
		// static SKYBRIDGE_ENROLLMENT_TOKEN, this can be minted on every restart — including a
		// redeployed task with a wiped disk — so it never hits the "token already consumed by the
		// task I'm replacing" failure mode a single-use token has.
		token, ierr := edgeiam.EnrollTokenViaIAM(ctx, edgeiam.IamEnrollConfig{
			BaseURL:  c.cfg.IamEnrollURL,
			Path:     DefaultIamEnrollTokenPath,
			TenantID: c.cfg.TenantID,
			AgentID:  c.cfg.ConnectorID,
		})
		if ierr != nil {
			if stored != nil {
				// Mint failed (e.g. control plane hiccup) but we still have a stale-but-usable
				// cert cached — prefer that over hard-failing the connection attempt.
				return &tlsMaterial{caBundlePEM: pickCA(), clientCertPEM: stored.ClientCertPEM, clientKeyPEM: stored.ClientKeyPEM}, nil
			}
			return nil, fmt.Errorf("IAM enroll-token: %w", ierr)
		}
		enrollToken = token
	}

	if enrollToken == "" {
		if stored != nil {
			// Expired but no token to renew — try anyway; the gateway rejects if invalid.
			return &tlsMaterial{caBundlePEM: pickCA(), clientCertPEM: stored.ClientCertPEM, clientKeyPEM: stored.ClientKeyPEM}, nil
		}
		return nil, errors.New("mTLS configured (CA bundle present) but no client cert and no SKYBRIDGE_ENROLLMENT_TOKEN to enroll")
	}

	m, err := c.enrollWithToken(ctx, enrollToken)
	if err != nil {
		return nil, err
	}
	if err := store.Save(ctx, &certstore.Material{CABundlePEM: m.caBundlePEM, ClientCertPEM: m.clientCertPEM, ClientKeyPEM: m.clientKeyPEM}); err != nil {
		return nil, err
	}
	return m, nil
}

// enroll generates a fresh keypair + CSR and exchanges c.cfg.EnrollToken (a one-time enrollment
// token) for a signed cert over a server-TLS channel (no client cert yet).
func (c *Client) enroll(ctx context.Context) (*tlsMaterial, error) {
	return c.enrollWithToken(ctx, c.cfg.EnrollToken)
}

// enrollWithToken is enroll's implementation, parameterized on the token so ensureTLSMaterial can
// pass a freshly IAM-minted one without mutating c.cfg.
func (c *Client) enrollWithToken(ctx context.Context, enrollToken string) (*tlsMaterial, error) {
	keyPEM, csrPEM, err := generateKeyAndCSR(c.cfg.TrustDomain, c.cfg.TenantID, c.cfg.ConnectorID)
	if err != nil {
		return nil, err
	}
	tlsCfg, err := serverTLSConfig(c.cfg.CABundlePEM)
	if err != nil {
		return nil, err
	}
	target := c.cfg.EnrollTarget
	if target == "" {
		target = c.cfg.Target
	}
	conn, err := grpc.NewClient(target, grpc.WithTransportCredentials(credentials.NewTLS(tlsCfg)))
	if err != nil {
		return nil, err
	}
	defer conn.Close()

	c.logger.Info(fmt.Sprintf("enrolling tenant=%s edge=%s via %s", c.cfg.TenantID, c.cfg.ConnectorID, target))
	resp, err := connectorv1.NewConnectorGatewayClient(conn).Enroll(ctx, &connectorv1.EnrollRequest{
		EnrollmentToken: enrollToken,
		TenantId:        c.cfg.TenantID,
		ConnectorId:     c.cfg.ConnectorID,
		CsrPem:          string(csrPEM),
	})
	if err != nil {
		return nil, err
	}
	caOut := []byte(resp.GetCaBundlePem())
	if len(caOut) == 0 {
		caOut = c.cfg.CABundlePEM
	}
	return &tlsMaterial{
		caBundlePEM:   caOut,
		clientCertPEM: []byte(resp.GetClientCertPem()),
		clientKeyPEM:  keyPEM,
	}, nil
}

// renewCert proactively refreshes the client cert using the CURRENT still-valid cert as proof of
// identity on the mTLS channel -- unlike enroll, no enrollment token is involved. Persists the
// result via the same certstore used by ensureTLSMaterial so a later restart picks up the renewed
// cert instead of the one it replaced.
func (c *Client) renewCert(ctx context.Context, current *tlsMaterial) (*tlsMaterial, error) {
	keyPEM, csrPEM, err := generateKeyAndCSR(c.cfg.TrustDomain, c.cfg.TenantID, c.cfg.ConnectorID)
	if err != nil {
		return nil, err
	}
	tlsCfg, err := mtlsTLSConfig(current)
	if err != nil {
		return nil, err
	}
	conn, err := grpc.NewClient(c.cfg.Target, grpc.WithTransportCredentials(credentials.NewTLS(tlsCfg)))
	if err != nil {
		return nil, err
	}
	defer conn.Close()

	resp, err := connectorv1.NewConnectorGatewayClient(conn).Renew(ctx, &connectorv1.RenewRequest{
		CsrPem: string(csrPEM),
	})
	if err != nil {
		return nil, err
	}
	caOut := []byte(resp.GetCaBundlePem())
	if len(caOut) == 0 {
		caOut = current.caBundlePEM
	}
	m := &tlsMaterial{
		caBundlePEM:   caOut,
		clientCertPEM: []byte(resp.GetClientCertPem()),
		clientKeyPEM:  keyPEM,
	}
	store := certstore.FromEnv(c.tlsDir(), c.cfg.IdentitySecretARN)
	if err := store.Save(ctx, &certstore.Material{CABundlePEM: m.caBundlePEM, ClientCertPEM: m.clientCertPEM, ClientKeyPEM: m.clientKeyPEM}); err != nil {
		return nil, err
	}
	return m, nil
}

// loadSVIDIfAvailable attempts to load a JWT-SVID from SPIRE.
// Returns a tlsMaterial with the SVID set if successful, or (nil, error) if SPIRE is unavailable
// or returns an expired SVID.
func (c *Client) loadSVIDIfAvailable(ctx context.Context) (*tlsMaterial, error) {
	loader := spire.NewSVIDLoader(c.cfg.SpireSocketPath)
	if !loader.IsAvailable() {
		return nil, errors.New("SPIRE socket path not available")
	}

	svid, err := loader.LoadSVID(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to load SVID from SPIRE: %w", err)
	}

	// Parse expiration from SVID (minimal validation).
	expiresAt, parseErr := extractSVIDExpiration(svid)
	if parseErr != nil {
		return nil, fmt.Errorf("failed to extract SVID expiration: %w", parseErr)
	}

	// Check if SVID is still valid.
	if err := spire.CheckExpiration(expiresAt); err != nil {
		return nil, fmt.Errorf("SVID is expired: %w", err)
	}

	c.logger.Info(fmt.Sprintf("loaded JWT-SVID from SPIRE (expires at %d)", expiresAt))
	return &tlsMaterial{svid: svid, expiresAt: expiresAt}, nil
}

func (c *Client) tlsDir() string {
	if c.cfg.TLSDir != "" {
		return c.cfg.TLSDir
	}
	return "/var/lib/skybridge/tls"
}

func certValid(certPEM []byte, skew time.Duration) bool {
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

// extractSVIDExpiration extracts the "exp" claim from a JWT-SVID.
// Returns the Unix timestamp or an error if parsing fails.
func extractSVIDExpiration(svid string) (int64, error) {
	// Split JWT: header.payload.signature
	parts := []string{}
	current := ""
	for _, ch := range svid {
		if ch == '.' {
			parts = append(parts, current)
			current = ""
		} else {
			current += string(ch)
		}
	}
	if current != "" {
		parts = append(parts, current)
	}

	if len(parts) != 3 {
		return 0, fmt.Errorf("invalid JWT: expected 3 parts, got %d", len(parts))
	}

	// Decode payload (base64url).
	payload := parts[1]
	// Add padding if needed (base64url in JWT is unpadded).
	padded := payload
	switch len(payload) % 4 {
	case 2:
		padded = payload + "=="
	case 3:
		padded = payload + "="
	}

	decoded, err := base64.URLEncoding.DecodeString(padded)
	if err != nil {
		return 0, fmt.Errorf("base64 decode failed: %w", err)
	}

	// Parse JSON to extract "exp" claim.
	var claims map[string]interface{}
	if err := json.Unmarshal(decoded, &claims); err != nil {
		return 0, fmt.Errorf("JSON unmarshal failed: %w", err)
	}

	// The "exp" claim should be a number (JSON float64 when unmarshaled).
	expVal, ok := claims["exp"]
	if !ok {
		return 0, fmt.Errorf("no 'exp' claim in SVID")
	}

	expFloat, ok := expVal.(float64)
	if !ok {
		return 0, fmt.Errorf("exp claim is not a number: %T", expVal)
	}

	return int64(expFloat), nil
}
