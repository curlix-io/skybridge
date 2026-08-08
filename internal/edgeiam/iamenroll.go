// Package edgeiam presigns an sts:GetCallerIdentity call with the edge's ambient AWS credentials
// (an ECS task role, in production) and exchanges it with the control plane for a short-lived
// enrollment token — no human-minted, single-use token needed. Shared by every edge enrollment
// surface (Skybridge connector, Query Studio, and the wire-mTLS tunnel — see
// internal/wiremtls/iamenroll.go, which wraps this package for backward compatibility).
//
// The resulting token is fed into that surface's *existing*, unmodified cert-issuance call (gRPC
// Enroll for connector/Studio, HTTP /enroll for wire-mTLS) — this package only replaces how the
// token is obtained, not how it's redeemed. See backend/src/curlix/edge_agents/iam_auth.py for
// the server-side verification this authenticates against.
package edgeiam

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
)

const enrollTimeout = 15 * time.Second

// IamEnrollConfig configures the presign-STS + POST-to-control-plane bootstrap for one enrollment
// surface. TenantID/AgentID are the JSON keys the control plane's iam auth endpoints expect
// (tenant_id/agent_id — connector_id is just this surface's name for "agent id"). Extra carries
// any additional body fields a specific surface needs (e.g. connector's studio_agent_id).
type IamEnrollConfig struct {
	BaseURL  string // control-plane HTTPS origin, e.g. https://api.curlix.io
	Path     string // e.g. /api/v1/skybridge/enrollments-iam or /api/v1/skybridge/wire-mtls/enroll-token-iam
	TenantID string
	AgentID  string
	Extra    map[string]string // additional JSON body fields, merged in alongside tenant_id/agent_id
}

type iamEnrollTokenResponseBody struct {
	EnrollToken string `json:"enroll_token"`
	// Connector/Studio's /enrollments-iam responds with `enrollment_token`; wire-mTLS's
	// /enroll-token-iam responds with `enroll_token`. Accept either key.
	EnrollmentToken string `json:"enrollment_token"`
	Detail          string `json:"detail"`
}

func (r iamEnrollTokenResponseBody) token() string {
	if r.EnrollToken != "" {
		return r.EnrollToken
	}
	return r.EnrollmentToken
}

// EnrollTokenViaIAM presigns a GetCallerIdentity call with the agent's ambient AWS credentials and
// exchanges it for a short-lived, single-use enrollment token — no human in the loop.
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
	url := strings.TrimRight(strings.TrimSpace(cfg.BaseURL), "/") + path

	bodyMap := map[string]any{
		"tenant_id":   cfg.TenantID,
		"agent_id":    cfg.AgentID,
		"sts_method":  presigned.Method,
		"sts_url":     presigned.URL,
		"sts_headers": headers,
	}
	for k, v := range cfg.Extra {
		bodyMap[k] = v
	}
	body, err := json.Marshal(bodyMap)
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
		return "", fmt.Errorf("IAM enroll-token: %w", err)
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
		return "", fmt.Errorf("IAM enroll-token rejected (%d): %s", resp.StatusCode, detail)
	}
	token := out.token()
	if token == "" {
		return "", fmt.Errorf("IAM enroll-token: empty token in response")
	}
	return token, nil
}
