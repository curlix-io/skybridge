package agent

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"strings"
	"time"

	"github.com/curlix-io/skybridge/internal/config"
)

// listenerCertReportTimeout mirrors k8sCredentialExchangeTimeout's rationale — this call happens
// once per process startup (not per connection), but must still not hang the startup path
// indefinitely if the control plane is briefly unreachable.
const listenerCertReportTimeout = 10 * time.Second

type listenerCertReportRequest struct {
	OrganizationID string `json:"organization_id"`
	Driver         string `json:"driver"`
	CertPEM        string `json:"cert_pem"`
}

// reportListenerCert self-reports this agent's client-facing listener cert (wire DB listener or K8s
// API listener) to the control plane, closing the "cert registration has no auto-discovery path"
// gap (docs/design/kubernetes-access-broker.md §11.5/§11.7) — an admin no longer has to manually
// `kubectl get secret ... | base64 -d` and paste the PEM into the Connectivity panel. Best-effort by
// design: called once at startup from a goroutine, logs a warning and returns without blocking
// serving traffic on any failure (network blip, control plane briefly down, URL not configured at
// all) — an admin can always fall back to the manual paste, so this is a convenience, not a
// dependency. driver is "postgres"/"mysql"/"mongo"/"kubernetes", matching
// enterprise_connectivity.VALID_WIRE_DRIVERS on the control-plane side.
func reportListenerCert(ctx context.Context, cfg config.Agent, driver string, certPEM []byte, logger *slog.Logger) {
	if logger == nil {
		logger = slog.Default()
	}
	url := strings.TrimSpace(cfg.ListenerCertReportURL)
	if url == "" || len(certPEM) == 0 {
		return
	}
	orgID := strings.TrimSpace(cfg.OrgID)
	if orgID == "" {
		logger.Warn("SKYBRIDGE_LISTENER_CERT_REPORT_URL is set but SKYBRIDGE_ORG_ID is not — skipping cert self-report")
		return
	}
	body, err := json.Marshal(listenerCertReportRequest{OrganizationID: orgID, Driver: driver, CertPEM: string(certPEM)})
	if err != nil {
		logger.Warn(fmt.Sprintf("listener cert report: marshal: %v", err))
		return
	}
	reqCtx, cancel := context.WithTimeout(ctx, listenerCertReportTimeout)
	defer cancel()
	req, err := http.NewRequestWithContext(reqCtx, http.MethodPost, url, bytes.NewReader(body))
	if err != nil {
		logger.Warn(fmt.Sprintf("listener cert report: build request: %v", err))
		return
	}
	req.Header.Set("Content-Type", "application/json")
	if token := strings.TrimSpace(cfg.CredentialExchangeToken); token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	resp, err := (&http.Client{Timeout: listenerCertReportTimeout}).Do(req)
	if err != nil {
		logger.Warn(fmt.Sprintf("listener cert report: %v", err))
		return
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		raw, _ := io.ReadAll(io.LimitReader(resp.Body, 4<<10))
		logger.Warn(fmt.Sprintf("listener cert report rejected (%d): %s", resp.StatusCode, string(raw)))
		return
	}
	logger.Info(fmt.Sprintf("reported %s listener cert to control plane (org=%s)", driver, orgID))
}
