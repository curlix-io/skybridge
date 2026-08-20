// Package certstore persists an enrolled edge's mTLS identity (ca.pem, client.crt, client.key)
// across process restarts. The default store is local disk (unchanged behavior). When
// SKYBRIDGE_IDENTITY_SECRET_ARN is set, the store additionally mirrors the material to an AWS
// Secrets Manager secret, so a replaced ECS task (new task ID, empty local disk) recovers its
// already-issued identity instead of re-enrolling with a one-time token that was already consumed.
package certstore

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
)

// Material is the cached identity bundle for one enrolled endpoint (edge, studio, or wire-mtls).
// Supports both traditional mTLS (cert/key) and SPIFFE JWT-SVID bearer tokens.
type Material struct {
	CABundlePEM   []byte `json:"ca_bundle_pem,omitempty"`
	ClientCertPEM []byte `json:"client_cert_pem,omitempty"`
	ClientKeyPEM  []byte `json:"client_key_pem,omitempty"`

	// SPIFFE/SPIRE JWT-SVID (optional alternative to mTLS certs).
	// When SVID is set, it's used as a bearer token instead of presenting ClientCertPEM.
	SVID      string `json:"svid,omitempty"`
	ExpiresAt int64  `json:"expires_at,omitempty"` // Unix timestamp when SVID expires
}

// Store loads and saves Material for a single logical identity.
type Store interface {
	// Load returns (nil, nil) when no material is cached yet.
	Load(ctx context.Context) (*Material, error)
	Save(ctx context.Context, m *Material) error
}

// diskStore is the original local-filesystem-only behavior: ca.pem, client.crt, client.key as
// separate files under dir.
type diskStore struct{ dir string }

// NewDiskStore returns a Store backed by three PEM files under dir.
func NewDiskStore(dir string) Store { return diskStore{dir: dir} }

func (s diskStore) Load(_ context.Context) (*Material, error) {
	cert := readFileOrNil(filepath.Join(s.dir, "client.crt"))
	key := readFileOrNil(filepath.Join(s.dir, "client.key"))
	if len(cert) == 0 || len(key) == 0 {
		return nil, nil
	}
	return &Material{
		CABundlePEM:   readFileOrNil(filepath.Join(s.dir, "ca.pem")),
		ClientCertPEM: cert,
		ClientKeyPEM:  key,
	}, nil
}

func (s diskStore) Save(_ context.Context, m *Material) error {
	if err := os.MkdirAll(s.dir, 0o755); err != nil {
		return err
	}
	if len(m.CABundlePEM) > 0 {
		if err := os.WriteFile(filepath.Join(s.dir, "ca.pem"), m.CABundlePEM, 0o644); err != nil {
			return err
		}
	}
	if err := os.WriteFile(filepath.Join(s.dir, "client.crt"), m.ClientCertPEM, 0o644); err != nil {
		return err
	}
	return os.WriteFile(filepath.Join(s.dir, "client.key"), m.ClientKeyPEM, 0o600)
}

// layered tries each store in order on Load (first hit wins) and writes through to all of them on
// Save, so a later replacement task can recover material a fresh disk lost.
type layered struct{ stores []Store }

// NewLayered combines stores, e.g. NewLayered(diskStore, secretsManagerStore) — disk stays the fast
// path; Secrets Manager (or another remote store) survives task/disk replacement.
func NewLayered(stores ...Store) Store { return layered{stores: stores} }

func (l layered) Load(ctx context.Context) (*Material, error) {
	for _, s := range l.stores {
		m, err := s.Load(ctx)
		if err != nil {
			return nil, err
		}
		if m != nil {
			return m, nil
		}
	}
	return nil, nil
}

func (l layered) Save(ctx context.Context, m *Material) error {
	for _, s := range l.stores {
		if err := s.Save(ctx, m); err != nil {
			return err
		}
	}
	return nil
}

func readFileOrNil(path string) []byte {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil
	}
	return b
}

// MarshalJSON / UnmarshalJSON helpers used by the Secrets Manager store to serialize Material as a
// single secret value.
func (m Material) toJSON() ([]byte, error) { return json.Marshal(m) }
func fromJSON(raw []byte) (*Material, error) {
	var m Material
	if err := json.Unmarshal(raw, &m); err != nil {
		return nil, err
	}
	return &m, nil
}
