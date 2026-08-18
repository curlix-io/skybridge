package agent

import (
	"context"
	"crypto/tls"
	"fmt"

	"github.com/curlix-io/skybridge/internal/certstore"
)

// ensureSelfSignedCert loads a previously generated cert/key pair from store (local disk, layered
// with AWS Secrets Manager when a secret ARN is configured — see certstore.FromEnv), or generates
// and persists a fresh one when none exists yet. This is the CloudFormation/ECS-deployable
// counterpart to the Helm chart's install-time `genSelfSignedCert` + `Secret` `lookup` pattern
// (docs/design/kubernetes-access-broker.md §11.7): ECS has no equivalent install-time templating,
// so the agent binary itself must own "generate once, persist, reuse on every restart" instead of
// getting a ready-made cert handed to it via env vars.
//
// Returns the cert/key PEM (for buildling a tls.Certificate and for reporting to the control plane,
// see certreport.go) so a redeployed task with fresh disk still presents the exact cert an admin
// may have already pinned via wire_listener_ca_pem, instead of silently invalidating that pinning
// on every restart.
func ensureSelfSignedCert(ctx context.Context, diskDir, secretARN string) (certPEM, keyPEM []byte, err error) {
	store := certstore.FromEnv(diskDir, secretARN)
	m, err := store.Load(ctx)
	if err != nil {
		return nil, nil, fmt.Errorf("load persisted self-signed cert: %w", err)
	}
	if m != nil && len(m.ClientCertPEM) > 0 && len(m.ClientKeyPEM) > 0 {
		return m.ClientCertPEM, m.ClientKeyPEM, nil
	}
	certPEM, keyPEM, err = generateSelfSignedCertPEM()
	if err != nil {
		return nil, nil, fmt.Errorf("generate self-signed cert: %w", err)
	}
	if err := store.Save(ctx, &certstore.Material{ClientCertPEM: certPEM, ClientKeyPEM: keyPEM}); err != nil {
		return nil, nil, fmt.Errorf("persist self-signed cert: %w", err)
	}
	return certPEM, keyPEM, nil
}

// tlsCertificateFromPEM is a small convenience wrapper so callers that only need the tls.Certificate
// (not the raw PEM) don't each repeat the X509KeyPair call.
func tlsCertificateFromPEM(certPEM, keyPEM []byte) (tls.Certificate, error) {
	return tls.X509KeyPair(certPEM, keyPEM)
}
