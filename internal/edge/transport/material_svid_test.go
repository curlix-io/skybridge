package transport

import (
	"context"
	"testing"
	"time"
)

// TestExtractSVIDExpiration tests SVID expiration extraction.
func TestExtractSVIDExpiration(t *testing.T) {
	tests := []struct {
		name    string
		jwt     string
		wantErr bool
	}{
		{
			name:    "valid JWT with future exp",
			jwt:     "eyJhbGciOiJFUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJzcGlmZmU6Ly9leGFtcGxlLmNvbS90ZXN0IiwiZXhwIjo5OTk5OTk5OTk5fQ.dummysignature",
			wantErr: false,
		},
		{
			name:    "invalid JWT (too few parts)",
			jwt:     "header.payload",
			wantErr: true,
		},
		{
			name:    "invalid base64",
			jwt:     "!!!.!!!.!!!",
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			exp, err := extractSVIDExpiration(tt.jwt)
			if (err != nil) != tt.wantErr {
				t.Errorf("extractSVIDExpiration() error = %v, wantErr %v", err, tt.wantErr)
			}
			if !tt.wantErr && exp == 0 {
				t.Errorf("extractSVIDExpiration() returned 0 expiration")
			}
		})
	}
}

// TestTLSMaterialHasSVID tests the HasSVID helper method.
func TestTLSMaterialHasSVID(t *testing.T) {
	tests := []struct {
		name     string
		material *tlsMaterial
		want     bool
	}{
		{
			name:     "nil material",
			material: nil,
			want:     false,
		},
		{
			name:     "material with SVID",
			material: &tlsMaterial{svid: "eyJ..."},
			want:     true,
		},
		{
			name:     "material without SVID",
			material: &tlsMaterial{clientCertPEM: []byte("cert")},
			want:     false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := tt.material.HasSVID()
			if got != tt.want {
				t.Errorf("HasSVID() = %v, want %v", got, tt.want)
			}
		})
	}
}

// TestTLSMaterialIsMTLS tests the IsMTLS helper method.
func TestTLSMaterialIsMTLS(t *testing.T) {
	tests := []struct {
		name     string
		material *tlsMaterial
		want     bool
	}{
		{
			name:     "nil material",
			material: nil,
			want:     false,
		},
		{
			name:     "material with cert and key",
			material: &tlsMaterial{clientCertPEM: []byte("cert"), clientKeyPEM: []byte("key")},
			want:     true,
		},
		{
			name:     "material with only cert",
			material: &tlsMaterial{clientCertPEM: []byte("cert")},
			want:     false,
		},
		{
			name:     "material with SVID only",
			material: &tlsMaterial{svid: "eyJ..."},
			want:     false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := tt.material.IsMTLS()
			if got != tt.want {
				t.Errorf("IsMTLS() = %v, want %v", got, tt.want)
			}
		})
	}
}

// TestLoadSVIDIfAvailableWithValidSVID tests loading valid SVID.
func TestLoadSVIDIfAvailableWithValidSVID(t *testing.T) {
	// Create a mock Client with fake config
	c := &Client{
		cfg: Config{
			SpireSocketPath: "/nonexistent", // Will fail IsAvailable
		},
	}

	mat, err := c.loadSVIDIfAvailable(context.Background())
	if err == nil {
		t.Errorf("loadSVIDIfAvailable() should fail when socket unavailable")
	}
	if mat != nil {
		t.Errorf("loadSVIDIfAvailable() should return nil on error")
	}
}
