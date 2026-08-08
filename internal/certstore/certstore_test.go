package certstore

import (
	"context"
	"errors"
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

func TestFromEnvBlankSecretARNReturnsDiskOnly(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "tls")
	store := FromEnv(dir, "   ")
	if _, ok := store.(diskStore); !ok {
		t.Fatalf("expected plain diskStore when secretARN is blank, got %T", store)
	}
}

func TestFromEnvWithSecretARNReturnsLayeredStore(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "tls")
	store := FromEnv(dir, "arn:aws:secretsmanager:us-east-1:123:secret:wire-mtls")
	if _, ok := store.(layered); !ok {
		t.Fatalf("expected layered store when secretARN is set, got %T", store)
	}
}

func TestDiskStoreSaveWithoutCABundleOmitsCAFile(t *testing.T) {
	dir := t.TempDir()
	store := NewDiskStore(dir)
	ctx := context.Background()

	if err := store.Save(ctx, &Material{ClientCertPEM: []byte("cert"), ClientKeyPEM: []byte("key")}); err != nil {
		t.Fatalf("save: %v", err)
	}
	got, err := store.Load(ctx)
	if err != nil || got == nil {
		t.Fatalf("load: %v err=%v", got, err)
	}
	if len(got.CABundlePEM) != 0 {
		t.Fatalf("expected no CA bundle to be persisted, got %q", got.CABundlePEM)
	}
	if string(got.ClientCertPEM) != "cert" || string(got.ClientKeyPEM) != "key" {
		t.Fatalf("unexpected material: %+v", got)
	}
}

func TestLayeredLoadPropagatesErrorFromFirstStore(t *testing.T) {
	first := &fakeStore{loadErr: errors.New("disk unreadable")}
	second := &fakeStore{loaded: &Material{ClientCertPEM: []byte("from-second")}}
	l := NewLayered(first, second)

	if _, err := l.Load(context.Background()); err == nil {
		t.Fatal("expected error from first store to propagate without falling through")
	}
}

func TestLayeredSaveStopsOnFirstError(t *testing.T) {
	first := &fakeStore{}
	failing := &failingSaveStore{err: errors.New("secrets manager down")}
	second := &fakeStore{}
	l := NewLayered(first, failing, second)

	err := l.Save(context.Background(), &Material{ClientCertPEM: []byte("cert"), ClientKeyPEM: []byte("key")})
	if err == nil {
		t.Fatal("expected error to propagate")
	}
	if first.saved == nil {
		t.Fatal("expected first store (before the failing one) to still receive the save")
	}
	if second.saved != nil {
		t.Fatal("expected stores after the failing one to be skipped")
	}
}

type failingSaveStore struct{ err error }

func (f *failingSaveStore) Load(context.Context) (*Material, error) { return nil, nil }
func (f *failingSaveStore) Save(context.Context, *Material) error   { return f.err }
