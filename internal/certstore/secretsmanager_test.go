package certstore

import (
	"context"
	"errors"
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/secretsmanager"
	"github.com/aws/aws-sdk-go-v2/service/secretsmanager/types"
)

// fakeSecretsManagerClient is a minimal in-memory secretsManagerAPI for testing without hitting AWS.
type fakeSecretsManagerClient struct {
	getOut  *secretsmanager.GetSecretValueOutput
	getErr  error
	putErr  error
	putCall *secretsmanager.PutSecretValueInput
}

func (f *fakeSecretsManagerClient) GetSecretValue(context.Context, *secretsmanager.GetSecretValueInput, ...func(*secretsmanager.Options)) (*secretsmanager.GetSecretValueOutput, error) {
	return f.getOut, f.getErr
}

func (f *fakeSecretsManagerClient) PutSecretValue(_ context.Context, in *secretsmanager.PutSecretValueInput, _ ...func(*secretsmanager.Options)) (*secretsmanager.PutSecretValueOutput, error) {
	f.putCall = in
	return &secretsmanager.PutSecretValueOutput{}, f.putErr
}

func TestSecretsManagerStoreLoadReturnsNilOnResourceNotFound(t *testing.T) {
	client := &fakeSecretsManagerClient{getErr: &types.ResourceNotFoundException{}}
	store := NewSecretsManagerStore(client, "arn:secret")

	m, err := store.Load(context.Background())
	if err != nil {
		t.Fatalf("expected nil error, got %v", err)
	}
	if m != nil {
		t.Fatalf("expected nil material when secret does not exist, got %v", m)
	}
}

func TestSecretsManagerStoreLoadPropagatesOtherErrors(t *testing.T) {
	client := &fakeSecretsManagerClient{getErr: errors.New("boom")}
	store := NewSecretsManagerStore(client, "arn:secret")

	_, err := store.Load(context.Background())
	if err == nil {
		t.Fatal("expected error to propagate")
	}
}

func TestSecretsManagerStoreLoadReturnsNilOnEmptySecretString(t *testing.T) {
	client := &fakeSecretsManagerClient{getOut: &secretsmanager.GetSecretValueOutput{SecretString: aws.String("")}}
	store := NewSecretsManagerStore(client, "arn:secret")

	m, err := store.Load(context.Background())
	if err != nil || m != nil {
		t.Fatalf("expected nil material for empty secret string, got %v err=%v", m, err)
	}
}

func TestSecretsManagerStoreLoadReturnsNilOnNonJSONLegacyToken(t *testing.T) {
	client := &fakeSecretsManagerClient{getOut: &secretsmanager.GetSecretValueOutput{SecretString: aws.String("plain-one-time-token")}}
	store := NewSecretsManagerStore(client, "arn:secret")

	m, err := store.Load(context.Background())
	if err != nil || m != nil {
		t.Fatalf("expected nil material for non-JSON legacy token, got %v err=%v", m, err)
	}
}

func TestSecretsManagerStoreLoadReturnsNilOnIncompleteMaterial(t *testing.T) {
	raw, err := (&Material{ClientCertPEM: []byte("cert-only")}).toJSON()
	if err != nil {
		t.Fatal(err)
	}
	client := &fakeSecretsManagerClient{getOut: &secretsmanager.GetSecretValueOutput{SecretString: aws.String(string(raw))}}
	store := NewSecretsManagerStore(client, "arn:secret")

	m, err := store.Load(context.Background())
	if err != nil || m != nil {
		t.Fatalf("expected nil material when key is missing, got %v err=%v", m, err)
	}
}

func TestSecretsManagerStoreLoadReturnsMaterialOnValidJSON(t *testing.T) {
	raw, err := (&Material{CABundlePEM: []byte("ca"), ClientCertPEM: []byte("cert"), ClientKeyPEM: []byte("key")}).toJSON()
	if err != nil {
		t.Fatal(err)
	}
	client := &fakeSecretsManagerClient{getOut: &secretsmanager.GetSecretValueOutput{
		SecretString: aws.String(string(raw)),
	}}
	store := NewSecretsManagerStore(client, "arn:secret")

	m, err := store.Load(context.Background())
	if err != nil || m == nil {
		t.Fatalf("expected material, got %v err=%v", m, err)
	}
	if string(m.CABundlePEM) != "ca" || string(m.ClientCertPEM) != "cert" || string(m.ClientKeyPEM) != "key" {
		t.Fatalf("unexpected material: %+v", m)
	}
}

func TestSecretsManagerStoreSavePutsJSONMaterial(t *testing.T) {
	client := &fakeSecretsManagerClient{}
	store := NewSecretsManagerStore(client, "arn:secret")

	want := &Material{CABundlePEM: []byte("ca"), ClientCertPEM: []byte("cert"), ClientKeyPEM: []byte("key")}
	if err := store.Save(context.Background(), want); err != nil {
		t.Fatal(err)
	}
	if client.putCall == nil {
		t.Fatal("expected PutSecretValue to be called")
	}
	if *client.putCall.SecretId != "arn:secret" {
		t.Fatalf("unexpected secret id: %q", *client.putCall.SecretId)
	}
	got, err := fromJSON([]byte(*client.putCall.SecretString))
	if err != nil {
		t.Fatal(err)
	}
	if string(got.ClientCertPEM) != "cert" || string(got.ClientKeyPEM) != "key" || string(got.CABundlePEM) != "ca" {
		t.Fatalf("unexpected saved material: %+v", got)
	}
}

func TestSecretsManagerStoreSavePropagatesError(t *testing.T) {
	client := &fakeSecretsManagerClient{putErr: errors.New("put failed")}
	store := NewSecretsManagerStore(client, "arn:secret")

	err := store.Save(context.Background(), &Material{ClientCertPEM: []byte("c"), ClientKeyPEM: []byte("k")})
	if err == nil {
		t.Fatal("expected error to propagate")
	}
}
