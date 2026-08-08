package wiremtls

import (
	"context"
	"fmt"
	"time"

	"github.com/curlix-io/skybridge/internal/certstore"
	"github.com/curlix-io/skybridge/internal/edgeiam"
)

// IamEnrollConfig configures the AWS-IAM-authenticated enroll-token bootstrap: the agent presigns
// its own sts:GetCallerIdentity call (using whatever ambient credentials it has — an ECS task
// role, in production) and the control plane replays it to STS to authenticate the caller, no
// human-minted token needed. See backend/src/curlix/edge_agents/iam_auth.py.
type IamEnrollConfig struct {
	BaseURL  string // control-plane origin, e.g. https://api.curlix.io
	Path     string // defaults to DefaultIamEnrollTokenPath
	TenantID string
	AgentID  string
}

// DefaultIamEnrollTokenPath is used when IamEnrollConfig.Path is empty.
const DefaultIamEnrollTokenPath = "/api/v1/skybridge/wire-mtls/enroll-token-iam"

// EnrollTokenViaIAM presigns a GetCallerIdentity call with the agent's ambient AWS credentials and
// exchanges it for a short-lived, single-use wire-mTLS enrollment token — no human in the loop.
// Thin wrapper over the shared internal/edgeiam package (used by every enrollment surface).
func EnrollTokenViaIAM(ctx context.Context, cfg IamEnrollConfig) (string, error) {
	path := cfg.Path
	if path == "" {
		path = DefaultIamEnrollTokenPath
	}
	return edgeiam.EnrollTokenViaIAM(ctx, edgeiam.IamEnrollConfig{
		BaseURL:  cfg.BaseURL,
		Path:     path,
		TenantID: cfg.TenantID,
		AgentID:  cfg.AgentID,
	})
}

var _ = fmt.Sprintf // keep fmt imported if unused below shrinks further

// IamEnrollTokenValidFor is how long a freshly-minted enroll token is expected to remain usable —
// mirrors ENROLL_TOKEN_TTL_SECONDS on the backend. Renewal loops should re-mint well before this.
const IamEnrollTokenValidFor = time.Hour

// EnsureMaterialViaIAM mints a fresh enroll token using the agent's ambient AWS identity (no
// static, human-minted token — see EnrollTokenViaIAM) and exchanges it for mTLS material through
// the existing enroll flow. Unlike EnsureMaterial's EnrollToken path, this can be called on every
// renewal (and every task restart) because minting the token itself needs no human step — solving
// the operability gap where a single-use human-minted token can't survive Fargate's ephemeral
// storage across restarts/redeploys.
func EnsureMaterialViaIAM(ctx context.Context, iamCfg IamEnrollConfig, cfg EnrollConfig) (*Material, error) {
	store := certstore.FromEnv(tlsDir(cfg.TLSDir), cfg.IdentitySecretARN)
	stored, err := store.Load(ctx)
	if err != nil {
		return nil, err
	}
	if stored != nil && CertValid(stored.ClientCertPEM, CertRenewSkew) {
		return EnsureMaterial(ctx, cfg)
	}

	token, err := EnrollTokenViaIAM(ctx, iamCfg)
	if err != nil {
		return nil, err
	}
	cfg.EnrollToken = token
	return EnsureMaterial(ctx, cfg)
}
