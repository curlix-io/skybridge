package certstore

import (
	"context"
	"path/filepath"
	"testing"
)

func TestDiskStoreRoundTrip(t *testing.T) {
	dir := t.TempDir()
	store := NewDiskStore(dir)
	ctx := context.Background()

	if m, err := store.Load(ctx); err != nil || m != nil {
		t.Fatalf("expected no material on empty dir, got %v err=%v", m, err)
	}

	want := &Material{CABundlePEM: []byte("ca"), ClientCertPEM: []byte("cert"), ClientKeyPEM: []byte("key")}
	if err := store.Save(ctx, want); err != nil {
		t.Fatalf("save: %v", err)
	}
	got, err := store.Load(ctx)
	if err != nil || got == nil {
		t.Fatalf("load: %v err=%v", got, err)
	}
	if string(got.ClientCertPEM) != "cert" || string(got.ClientKeyPEM) != "key" || string(got.CABundlePEM) != "ca" {
		t.Fatalf("unexpected material: %+v", got)
	}
}

// fakeStore is an in-memory Store for testing NewLayered fallback/write-through behavior.
type fakeStore struct {
	loaded  *Material
	loadErr error
	saved   *Material
}

func (f *fakeStore) Load(context.Context) (*Material, error) { return f.loaded, f.loadErr }
func (f *fakeStore) Save(_ context.Context, m *Material) error {
	f.saved = m
	return nil
}

func TestLayeredLoadFallsThroughToSecondStore(t *testing.T) {
	first := &fakeStore{loaded: nil}
	second := &fakeStore{loaded: &Material{ClientCertPEM: []byte("from-second")}}
	l := NewLayered(first, second)

	m, err := l.Load(context.Background())
	if err != nil || m == nil || string(m.ClientCertPEM) != "from-second" {
		t.Fatalf("expected material from second store, got %v err=%v", m, err)
	}
}

func TestLayeredSaveWritesToAllStores(t *testing.T) {
	first := &fakeStore{}
	second := &fakeStore{}
	l := NewLayered(first, second)

	want := &Material{ClientCertPEM: []byte("cert"), ClientKeyPEM: []byte("key")}
	if err := l.Save(context.Background(), want); err != nil {
		t.Fatalf("save: %v", err)
	}
	if first.saved == nil || string(first.saved.ClientCertPEM) != "cert" {
		t.Fatalf("expected first store to receive save, got %v", first.saved)
	}
	if second.saved == nil || string(second.saved.ClientCertPEM) != "cert" {
		t.Fatalf("expected second store to receive save, got %v", second.saved)
	}
}

func TestFromEnvNoSecretARNReturnsDiskOnly(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "tls")
	store := FromEnv(dir, "")
	if _, ok := store.(diskStore); !ok {
		t.Fatalf("expected plain diskStore when secretARN is empty, got %T", store)
	}
}
