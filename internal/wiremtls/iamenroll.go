package wiremtls

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	awsconfig "github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/sts"

	"github.com/curlix-io/skybridge/internal/certstore"
)

// IamEnrollConfig configures the AWS-IAM-authenticated enroll-token bootstrap: the agent presigns
// its own sts:GetCallerIdentity call (using whatever ambient credentials it has — an ECS task
// role, in production) and the control plane replays it to STS to authenticate the caller, no
// human-minted token needed. See backend/src/curlix/wire_mtls/iam_auth.py.
type IamEnrollConfig struct {
	BaseURL  string // control-plane origin, e.g. https://api.curlix.io
	Path     string // defaults to DefaultIamEnrollTokenPath
	TenantID string
	AgentID  string
}

// DefaultIamEnrollTokenPath is used when IamEnrollConfig.Path is empty.
const DefaultIamEnrollTokenPath = "/api/v1/skybridge/wire-mtls/enroll-token-iam"

type iamEnrollTokenRequestBody struct {
	TenantID   string            `json:"tenant_id"`
	AgentID    string            `json:"agent_id"`
	StsMethod  string            `json:"sts_method"`
	StsURL     string            `json:"sts_url"`
	StsHeaders map[string]string `json:"sts_headers"`
}

type iamEnrollTokenResponseBody struct {
	EnrollToken string `json:"enroll_token"`
	Detail      string `json:"detail"`
}

// EnrollTokenViaIAM presigns a GetCallerIdentity call with the agent's ambient AWS credentials and
// exchanges it for a short-lived, single-use wire-mTLS enrollment token — no human in the loop.
func EnrollTokenViaIAM(ctx context.Context, cfg IamEnrollConfig) (string, error) {
	awsCfg, err := awsconfig.LoadDefaultConfig(ctx)
	if err != nil {
		return "", fmt.Errorf("load AWS config: %w", err)
	}
	presignClient := sts.NewPresignClient(sts.NewFromConfig(awsCfg))
	presigned, err := presignClient.PresignGetCallerIdentity(ctx, &sts.GetCallerIdentityInput{})
	if err != nil {
		return "", fmt.Errorf("presign GetCallerIdentity: %w", err)
	}

	headers := make(map[string]string, len(presigned.SignedHeader))
	for k, v := range presigned.SignedHeader {
		if len(v) > 0 {
			headers[k] = v[0]
		}
	}

	path := strings.TrimSpace(cfg.Path)
	if path == "" {
		path = DefaultIamEnrollTokenPath
	}
	url := strings.TrimRight(strings.TrimSpace(cfg.BaseURL), "/") + path

	body, err := json.Marshal(iamEnrollTokenRequestBody{
		TenantID:   cfg.TenantID,
		AgentID:    cfg.AgentID,
		StsMethod:  presigned.Method,
		StsURL:     presigned.URL,
		StsHeaders: headers,
	})
	if err != nil {
		return "", err
	}

	client := &http.Client{Timeout: enrollTimeout}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(body))
	if err != nil {
		return "", err
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := client.Do(req)
	if err != nil {
		return "", fmt.Errorf("wire mTLS IAM enroll-token: %w", err)
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	var out iamEnrollTokenResponseBody
	_ = json.Unmarshal(raw, &out)
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		detail := strings.TrimSpace(out.Detail)
		if detail == "" {
			detail = strings.TrimSpace(string(raw))
		}
		return "", fmt.Errorf("wire mTLS IAM enroll-token rejected (%d): %s", resp.StatusCode, detail)
	}
	if out.EnrollToken == "" {
		return "", fmt.Errorf("wire mTLS IAM enroll-token: empty token in response")
	}
	return out.EnrollToken, nil
}

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
