package spire

import (
	"context"
	"os"
	"testing"
	"time"
)

// TestSVIDLoaderIsAvailable tests that IsAvailable correctly detects socket availability.
func TestSVIDLoaderIsAvailable(t *testing.T) {
	tests := []struct {
		name       string
		socketPath string
		want       bool
	}{
		{
			name:       "empty path",
			socketPath: "",
			want:       false,
		},
		{
			name:       "non-existent path",
			socketPath: "/nonexistent/path/to/socket",
			want:       false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			loader := NewSVIDLoader(tt.socketPath)
			got := loader.IsAvailable()
			if got != tt.want {
				t.Errorf("IsAvailable() = %v, want %v", got, tt.want)
			}
		})
	}
}

// TestLoadSVIDErrors tests error cases for LoadSVID.
func TestLoadSVIDErrors(t *testing.T) {
	tests := []struct {
		name       string
		socketPath string
		wantErr    bool
	}{
		{
			name:       "empty socket path",
			socketPath: "",
			wantErr:    true,
		},
		{
			name:       "non-existent file",
			socketPath: "/nonexistent/svid.jwt",
			wantErr:    true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			loader := NewSVIDLoader(tt.socketPath)
			_, err := loader.LoadSVID(context.Background())
			if (err != nil) != tt.wantErr {
				t.Errorf("LoadSVID() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

// TestCheckExpirationValid tests SVID expiration checking.
func TestCheckExpirationValid(t *testing.T) {
	tests := []struct {
		name      string
		expiresAt int64
		wantErr   bool
	}{
		{
			name:      "future expiration",
			expiresAt: time.Now().Unix() + 3600, // 1 hour in the future
			wantErr:   false,
		},
		{
			name:      "far future expiration",
			expiresAt: time.Now().Unix() + 86400, // 1 day in the future
			wantErr:   false,
		},
		{
			name:      "expired",
			expiresAt: time.Now().Unix() - 100, // 100 seconds ago
			wantErr:   true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := CheckExpiration(tt.expiresAt)
			if (err != nil) != tt.wantErr {
				t.Errorf("CheckExpiration() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

// TestBase64URLDecode tests base64url decoding.
func TestBase64URLDecode(t *testing.T) {
	tests := []struct {
		name    string
		input   string
		want    string
		wantErr bool
	}{
		{
			name:    "simple string with padding",
			input:   "aGVsbG8=", // "hello" in base64url
			want:    "hello",
			wantErr: false,
		},
		{
			name:    "invalid base64",
			input:   "!!!invalid!!!",
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := base64URLDecode(tt.input)
			if (err != nil) != tt.wantErr {
				t.Errorf("base64URLDecode() error = %v, wantErr %v", err, tt.wantErr)
			}
			if !tt.wantErr && string(got) != tt.want {
				t.Errorf("base64URLDecode() = %s, want %s", string(got), tt.want)
			}
		})
	}
}

// TestSplitJWT tests JWT splitting into parts.
func TestSplitJWT(t *testing.T) {
	tests := []struct {
		name    string
		input   string
		wantLen int
	}{
		{
			name:    "valid JWT",
			input:   "header.payload.signature",
			wantLen: 3,
		},
		{
			name:    "two parts",
			input:   "header.payload",
			wantLen: 2,
		},
		{
			name:    "single part",
			input:   "header",
			wantLen: 1,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := splitJWT(tt.input)
			if len(got) != tt.wantLen {
				t.Errorf("splitJWT() len = %d, want %d", len(got), tt.wantLen)
			}
		})
	}
}

// TestLoadSVIDWithFile tests LoadSVID with an actual file.
func TestLoadSVIDWithFile(t *testing.T) {
	// Create a temporary file with a minimal valid JWT.
	// Format: header.payload.signature where:
	// header = {"alg":"ES256","typ":"JWT"}
	// payload = {"sub":"spiffe://example.com/test","exp":9999999999}
	// signature = dummy (not validated by LoadSVID, just structural check)
	tmpFile, err := os.CreateTemp("", "svid-*.jwt")
	if err != nil {
		t.Fatalf("CreateTemp failed: %v", err)
	}
	defer os.Remove(tmpFile.Name())

	// Write a minimal JWT (unverified, just for LoadSVID to parse).
	jwtData := "eyJhbGciOiJFUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJzcGlmZmU6Ly9leGFtcGxlLmNvbS90ZXN0IiwiZXhwIjo5OTk5OTk5OTk5fQ.dummysignature"
	if _, err := tmpFile.WriteString(jwtData); err != nil {
		t.Fatalf("WriteString failed: %v", err)
	}
	tmpFile.Close()

	loader := NewSVIDLoader(tmpFile.Name())
	if !loader.IsAvailable() {
		t.Errorf("IsAvailable() returned false for existing file")
	}

	svid, err := loader.LoadSVID(context.Background())
	if err != nil {
		t.Errorf("LoadSVID() failed: %v", err)
	}
	if svid != jwtData {
		t.Errorf("LoadSVID() returned %q, want %q", svid, jwtData)
	}
}
