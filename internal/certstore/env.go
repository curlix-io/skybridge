package certstore

import (
	"context"
	"strings"

	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/secretsmanager"
)

// FromEnv builds the Store for one identity: local disk at dir, layered with an AWS Secrets
// Manager secret when secretARNEnv names a non-empty secret ARN/name. secretARNEnv is typically
// one of SKYBRIDGE_IDENTITY_SECRET_ARN, SKYBRIDGE_STUDIO_IDENTITY_SECRET_ARN, or
// SKYBRIDGE_WIRE_MTLS_IDENTITY_SECRET_ARN — each edge/studio/wire-mtls identity gets its own secret
// so a redeployed task recovers exactly the cert it already had, without re-consuming a one-time
// enrollment token.
func FromEnv(dir, secretARN string) Store {
	disk := NewDiskStore(dir)
	secretARN = strings.TrimSpace(secretARN)
	if secretARN == "" {
		return disk
	}
	cfg, err := config.LoadDefaultConfig(context.Background())
	if err != nil {
		return disk
	}
	return NewLayered(disk, NewSecretsManagerStore(secretsmanager.NewFromConfig(cfg), secretARN))
}
