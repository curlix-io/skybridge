package certstore

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"log"

	"github.com/curlix-io/skybridge/internal/spire"
)

// SVIDStore loads JWT-SVIDs from SPIRE and uses them as bearer tokens.
// Falls back to a chained Store (e.g., diskStore or secretsStore) when SVID is unavailable.
type SVIDStore struct {
	svidLoader *spire.SVIDLoader
	fallback   Store // Fallback store (e.g., disk or secrets manager) for when SVID is unavailable
}

// NewSVIDStore creates a new SVIDStore with an optional fallback.
func NewSVIDStore(loader *spire.SVIDLoader, fallback Store) *SVIDStore {
	return &SVIDStore{
		svidLoader: loader,
		fallback:   fallback,
	}
}

// Load attempts to load a JWT-SVID from SPIRE. If successful, returns Material with the SVID
// as a bearer token. Falls back to the chained store on error.
func (s *SVIDStore) Load(ctx context.Context) (*Material, error) {
	if s.svidLoader == nil {
		// No SVID loader configured; use fallback immediately.
		if s.fallback != nil {
			return s.fallback.Load(ctx)
		}
		return nil, nil
	}

	// Try to load SVID from SPIRE.
	svid, err := s.svidLoader.LoadSVID(ctx)
	if err == nil {
		// SVID loaded successfully. Parse and validate expiration.
		expiresAt, err := parseSVIDExpiration(svid)
		if err != nil {
			log.Printf("[svid_store] failed to extract SVID expiration: %v", err)
			// Fall through to fallback if parsing fails.
		} else {
			// Check if SVID is expired.
			if err := spire.CheckExpiration(expiresAt); err == nil {
				log.Printf("[svid_store] loaded SVID from SPIRE (expires at %d)", expiresAt)
				return &Material{
					SVID:      svid,
					ExpiresAt: expiresAt,
				}, nil
			}
			// SVID is expired; fall through to fallback.
			log.Printf("[svid_store] SVID is expired: %v", err)
		}
	} else {
		log.Printf("[svid_store] failed to load SVID: %v", err)
	}

	// SVID unavailable or expired; fall back to chained store.
	if s.fallback != nil {
		return s.fallback.Load(ctx)
	}
	return nil, nil
}

// Save is a no-op for SVIDs (read-only from SPIRE). If a fallback store is configured,
// SVIDs are never persisted there — only mTLS certs would be.
func (s *SVIDStore) Save(ctx context.Context, m *Material) error {
	// SVIDs are read-only from SPIRE and ephemeral; we don't save them.
	if m.SVID != "" {
		// SVID material: nothing to persist.
		return nil
	}

	// Non-SVID material (mTLS certs): persist to fallback if present.
	if s.fallback != nil {
		return s.fallback.Save(ctx, m)
	}
	return nil
}

// parseSVIDExpiration extracts the expiration timestamp from a JWT-SVID's "exp" claim.
// Returns the Unix timestamp or an error if parsing fails.
func parseSVIDExpiration(svid string) (int64, error) {
	// Split JWT into parts: header.payload.signature
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
		return 0, fmt.Errorf("invalid JWT format: expected 3 parts, got %d", len(parts))
	}

	// Decode the payload (base64url).
	payload := parts[1]
	decoded, err := decodeBase64URL(payload)
	if err != nil {
		return 0, fmt.Errorf("payload decode failed: %w", err)
	}

	// Parse JSON to extract "exp" claim.
	exp, err := extractExpFromJSON(decoded)
	if err != nil {
		return 0, fmt.Errorf("extract exp failed: %w", err)
	}

	return exp, nil
}

// decodeBase64URL decodes a base64url-encoded string (JWT standard).
func decodeBase64URL(s string) ([]byte, error) {
	// Add padding if needed (base64url in JWT is unpadded).
	padded := s
	switch len(s) % 4 {
	case 2:
		padded = s + "=="
	case 3:
		padded = s + "="
	}

	return base64.URLEncoding.DecodeString(padded)
}

// extractExpFromJSON extracts the "exp" claim from a JSON payload.
// Returns the exp value as an int64 Unix timestamp.
func extractExpFromJSON(payload []byte) (int64, error) {
	var claims map[string]interface{}
	if err := json.Unmarshal(payload, &claims); err != nil {
		return 0, err
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
