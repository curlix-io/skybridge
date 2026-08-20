// Package spire provides JWT-SVID loading from a SPIRE workload API socket.
// SVIDs are short-lived cryptographic identities issued by SPIRE and consumed by
// the Skybridge connector for authentication to the connector gateway instead of
// enrolling an mTLS certificate or sharing a static bearer token.
//
// See docs/design/kubernetes-access-broker.md §12 ("SPIFFE-based identity").
package spire

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"os"
	"time"
)

// SVIDLoaderInterface is the interface for loading JWT-SVIDs from SPIRE.
// Allows mocking and dependency injection.
type SVIDLoaderInterface interface {
	IsAvailable() bool
	LoadSVID(ctx context.Context) (string, error)
}

// SVIDLoader reads JWT-SVIDs from a SPIRE workload API socket.
type SVIDLoader struct {
	socketPath string // e.g., /run/spiffe/agent.jwt (file path, not socket)
}

// NewSVIDLoader creates a new SVIDLoader with the given socket path.
func NewSVIDLoader(socketPath string) *SVIDLoader {
	return &SVIDLoader{socketPath: socketPath}
}

// LoadSVID reads a fresh JWT-SVID from the configured socket path.
// Returns the raw JWT string or an error if the file cannot be read or is invalid.
func (l *SVIDLoader) LoadSVID(ctx context.Context) (string, error) {
	if l.socketPath == "" {
		return "", errors.New("SVID socket path not configured")
	}

	// Read the file from the configured path.
	data, err := os.ReadFile(l.socketPath)
	if err != nil {
		return "", fmt.Errorf("failed to read SVID file: %w", err)
	}

	jwt := string(data)
	if jwt == "" {
		return "", errors.New("SVID file is empty")
	}

	// Quick validation: JWT must be three dot-separated parts (header.payload.signature).
	// This is a minimal sanity check; full verification happens in spiffe_auth.go.
	parts := splitJWT(jwt)
	if len(parts) != 3 {
		return "", fmt.Errorf("invalid JWT format: expected 3 parts, got %d", len(parts))
	}

	// Attempt to decode the payload to verify it's valid JSON and check the expiration.
	// (Full signature verification is deferred to the spiffe_auth layer.)
	claims, err := decodeJWTClaims(parts[1])
	if err != nil {
		return "", fmt.Errorf("failed to decode JWT payload: %w", err)
	}

	// Check if SVID is already expired.
	if expiresAt, ok := claims["exp"].(float64); ok {
		if time.Now().Unix() > int64(expiresAt) {
			return "", fmt.Errorf("SVID is expired (exp: %d, now: %d)", int64(expiresAt), time.Now().Unix())
		}
	}

	return jwt, nil
}

// IsAvailable checks if the SPIRE socket path exists and is readable.
func (l *SVIDLoader) IsAvailable() bool {
	if l.socketPath == "" {
		return false
	}
	info, err := os.Stat(l.socketPath)
	if err != nil {
		return false
	}
	// Ensure it's a regular file (not a directory or special file).
	return info.Mode().IsRegular()
}

// splitJWT splits a JWT into its three dot-separated parts.
func splitJWT(token string) []string {
	parts := []string{}
	current := ""
	for _, ch := range token {
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
	return parts
}

// decodeJWTClaims decodes the payload part of a JWT (base64url-encoded JSON).
// Returns the claims as a map[string]interface{} for minimal introspection.
func decodeJWTClaims(payload string) (map[string]interface{}, error) {
	// Decode base64url (JWT uses base64url without padding).
	// The crypto/base64 package handles padding automatically, so add it back.
	padded := payload
	switch len(payload) % 4 {
	case 2:
		padded = payload + "=="
	case 3:
		padded = payload + "="
	}

	decoded, err := base64URLDecode(padded)
	if err != nil {
		return nil, fmt.Errorf("base64 decode failed: %w", err)
	}

	var claims map[string]interface{}
	if err := json.Unmarshal(decoded, &claims); err != nil {
		return nil, fmt.Errorf("JSON unmarshal failed: %w", err)
	}

	return claims, nil
}

// base64URLDecode decodes a base64url-encoded string.
func base64URLDecode(s string) ([]byte, error) {
	return base64.URLEncoding.DecodeString(s)
}

// Logger wraps logging for SVID operations.
func logDebug(msg string, args ...interface{}) {
	log.Printf("[spire] "+msg, args...)
}

func logWarn(msg string, args ...interface{}) {
	log.Printf("[spire WARNING] "+msg, args...)
}

func logError(msg string, args ...interface{}) {
	log.Printf("[spire ERROR] "+msg, args...)
}

// ExpirationSkew is the allowed clock skew when checking SVID expiration (defensive buffer).
// In production, this should be tuned based on clock drift tolerance.
const ExpirationSkew = 30 * time.Second

// CheckExpiration checks if an SVID is still valid given a skew tolerance.
func CheckExpiration(expiresAtUnix int64) error {
	now := time.Now().Unix()
	expiry := expiresAtUnix
	if now > expiry+int64(ExpirationSkew.Seconds()) {
		return fmt.Errorf("SVID expired: exp=%d, now=%d, skew=%v", expiry, now, ExpirationSkew)
	}
	return nil
}
