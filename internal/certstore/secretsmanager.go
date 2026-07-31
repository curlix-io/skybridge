package certstore

import (
	"context"
	"errors"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/secretsmanager"
	"github.com/aws/aws-sdk-go-v2/service/secretsmanager/types"
)

// secretsManagerAPI is the subset of the Secrets Manager client this package needs, so tests can
// supply a fake instead of hitting AWS.
type secretsManagerAPI interface {
	GetSecretValue(ctx context.Context, in *secretsmanager.GetSecretValueInput, optFns ...func(*secretsmanager.Options)) (*secretsmanager.GetSecretValueOutput, error)
	PutSecretValue(ctx context.Context, in *secretsmanager.PutSecretValueInput, optFns ...func(*secretsmanager.Options)) (*secretsmanager.PutSecretValueOutput, error)
}

type secretsManagerStore struct {
	client   secretsManagerAPI
	secretID string
}

// NewSecretsManagerStore returns a Store that persists Material as a single JSON secret value at
// secretID (an ARN or name). Intended to be layered after a diskStore via NewLayered so redeployed
// ECS tasks recover the identity issued on first enrollment instead of re-enrolling.
func NewSecretsManagerStore(client secretsManagerAPI, secretID string) Store {
	return secretsManagerStore{client: client, secretID: secretID}
}

func (s secretsManagerStore) Load(ctx context.Context) (*Material, error) {
	out, err := s.client.GetSecretValue(ctx, &secretsmanager.GetSecretValueInput{SecretId: aws.String(s.secretID)})
	if err != nil {
		var nf *types.ResourceNotFoundException
		if errors.As(err, &nf) {
			return nil, nil
		}
		return nil, err
	}
	if out.SecretString == nil || *out.SecretString == "" {
		return nil, nil
	}
	m, err := fromJSON([]byte(*out.SecretString))
	if err != nil {
		// A pre-existing plaintext one-time enrollment token (not JSON) is not identity material.
		return nil, nil
	}
	if len(m.ClientCertPEM) == 0 || len(m.ClientKeyPEM) == 0 {
		return nil, nil
	}
	return m, nil
}

func (s secretsManagerStore) Save(ctx context.Context, m *Material) error {
	raw, err := m.toJSON()
	if err != nil {
		return err
	}
	_, err = s.client.PutSecretValue(ctx, &secretsmanager.PutSecretValueInput{
		SecretId:     aws.String(s.secretID),
		SecretString: aws.String(string(raw)),
	})
	return err
}
