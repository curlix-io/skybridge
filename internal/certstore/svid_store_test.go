package certstore

import (
	"context"
	"os"
	"testing"
	"time"
)

// TestSVIDStoreLoadWithAvailableSVID tests loading a valid SVID.
func TestSVIDStoreLoadWithAvailableSVID(t *testing.T) {
	// Create temporary SVID file with valid JWT
	tmpFile, err := os.CreateTemp("", "svid-*.jwt")
	if err != nil {
		t.Fatalf("CreateTemp failed: %v", err)
	}
	defer os.Remove(tmpFile.Name())

	// Valid JWT with exp claim in the future
	futureExp := time.Now().Unix() + 3600 // 1 hour from now
	jwtData := "eyJhbGciOiJFUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJzcGlmZmU6Ly9leGFtcGxlLmNvbS90ZXN0IiwiZXhwIjo5OTk5OTk5OTk5fQ.dummysignature"
	if _, err := tmpFile.WriteString(jwtData); err != nil {
		t.Fatalf("WriteString failed: %v", err)
	}
	tmpFile.Close()

	// Create a minimal loader
	mockLoader := &mockSVIDLoader{
		available: true,
		svid:      jwtData,
		expTime:   futureExp,
	}

	store := &SVIDStore{
		svidLoader: mockLoader,
		fallback:   nil,
	}

	mat, err := store.Load(context.Background())
	if err != nil {
		t.Errorf("Load() failed: %v", err)
	}
	if mat == nil {
		t.Errorf("Load() returned nil material")
	}
	if mat.SVID == "" {
		t.Errorf("Load() material has empty SVID")
	}
}

// TestSVIDStoreLoadFallbackWhenSVIDUnavailable tests fallback to chained store.
func TestSVIDStoreLoadFallbackWhenSVIDUnavailable(t *testing.T) {
	mockLoader := &mockSVIDLoader{
		available: false,
		err:       "socket not available",
	}

	fallbackMat := &Material{
		ClientCertPEM: []byte("fallback-cert"),
		ClientKeyPEM:  []byte("fallback-key"),
	}
	mockFallback := &mockStore{loaded: fallbackMat}

	store := &SVIDStore{
		svidLoader: mockLoader,
		fallback:   mockFallback,
	}

	mat, err := store.Load(context.Background())
	if err != nil {
		t.Errorf("Load() failed: %v", err)
	}
	if mat == nil {
		t.Errorf("Load() returned nil material")
	}
	if mat.SVID != "" {
		t.Errorf("Load() should not have SVID when fallback is used")
	}
	if string(mat.ClientCertPEM) != "fallback-cert" {
		t.Errorf("Load() didn't return fallback cert")
	}
}

// TestSVIDStoreSaveIsNoOp tests that Save is a no-op for SVID material.
func TestSVIDStoreSaveIsNoOp(t *testing.T) {
	mockFallback := &mockStore{}
	store := &SVIDStore{
		svidLoader: nil,
		fallback:   mockFallback,
	}

	svidMat := &Material{
		SVID: "eyJhbGciOiJFUzI1NiIsInR5cCI6IkpXVCJ9...",
	}

	err := store.Save(context.Background(), svidMat)
	if err != nil {
		t.Errorf("Save() failed: %v", err)
	}
	// Verify fallback.Save was NOT called for SVID material
	if mockFallback.saved {
		t.Errorf("Save() should not persist SVID material to fallback")
	}
}

// TestSVIDStoreSaveFallsBackForCerts tests that Save delegates to fallback for cert material.
func TestSVIDStoreSaveFallsBackForCerts(t *testing.T) {
	mockFallback := &mockStore{}
	store := &SVIDStore{
		svidLoader: nil,
		fallback:   mockFallback,
	}

	certMat := &Material{
		ClientCertPEM: []byte("cert"),
		ClientKeyPEM:  []byte("key"),
	}

	err := store.Save(context.Background(), certMat)
	if err != nil {
		t.Errorf("Save() failed: %v", err)
	}
	// Verify fallback.Save was called for cert material
	if !mockFallback.saved {
		t.Errorf("Save() should persist cert material to fallback")
	}
}

// mockSVIDLoader is a test helper for mocking SPIRE SVID loading.
type mockSVIDLoader struct {
	available bool
	svid      string
	expTime   int64
	err       string
}

func (m *mockSVIDLoader) IsAvailable() bool {
	return m.available
}

func (m *mockSVIDLoader) LoadSVID(ctx context.Context) (string, error) {
	if m.err != "" {
		return "", &mockError{msg: m.err}
	}
	return m.svid, nil
}

type mockError struct {
	msg string
}

func (e *mockError) Error() string {
	return e.msg
}

// mockStore is a test helper for mocking the fallback store.
type mockStore struct {
	loaded *Material
	saved  bool
	err    error
}

func (m *mockStore) Load(ctx context.Context) (*Material, error) {
	return m.loaded, m.err
}

func (m *mockStore) Save(ctx context.Context, mat *Material) error {
	m.saved = true
	return m.err
}
