//go:build querystudio

package main

import (
	"context"
	"log"

	"github.com/curlix-io/skybridge/internal/config"
	"github.com/curlix-io/skybridge/internal/edge"
	"github.com/curlix-io/skybridge/internal/edge/dbexec"
	"github.com/curlix-io/skybridge/internal/edge/dbquery"
	"github.com/curlix-io/skybridge/internal/edge/studiotransport"
	"github.com/curlix-io/skybridge/internal/mask"
)

// registerQueryStudioExtras wires up the Query Studio subsystems: the db_query_* one-shot exec
// tools (registered on reg, dispatched over the connector-gateway transport already running in
// main.go) and the second, independent Studio Gateway dial for Query Studio's own dispatch.
func registerQueryStudioExtras(ctx context.Context, cfg config.Edge, reg *edge.Registry, masker mask.Masker, logger *log.Logger) {
	execTargets := dbquery.MergeWireTargets(dbquery.ParseTargets(cfg.StudioTargetsJSON), cfg.WireProxy.Targets)
	dbexec.Register(reg, dbexec.Options{
		Targets:          execTargets,
		FallbackUser:     cfg.StudioDBUser,
		FallbackPassword: cfg.StudioDBPassword,
		Masker:           masker,
		OrgID:            cfg.TenantID,
	})
	dbexec.RegisterMigration(reg, dbexec.MigrationOptions{
		Targets:          execTargets,
		FallbackUser:     cfg.StudioDBUser,
		FallbackPassword: cfg.StudioDBPassword,
	})

	if !cfg.StudioEnabled() {
		return
	}
	studioCfg := studiotransport.Config{
		Target:            cfg.StudioGateway,
		TenantID:          cfg.TenantID,
		AgentID:           cfg.StudioAgentID,
		Token:             cfg.Token,
		Insecure:          cfg.Insecure,
		Reconnect:         true,
		MaxSessions:       cfg.StudioMaxSessions,
		Targets:           studiotransport.ParseTargets(cfg.StudioTargetsJSON),
		DBUser:            cfg.StudioDBUser,
		DBPassword:        cfg.StudioDBPassword,
		Masker:            masker,
		CABundlePEM:       cfg.CABundle,
		TLSDir:            cfg.StudioTLSDir,
		IdentitySecretARN: cfg.StudioIdentitySecretARN,
		EnrollTarget:      cfg.StudioEnrollGateway,
		EnrollToken:       cfg.StudioEnrollmentToken,
		TrustDomain:       cfg.StudioTrustDomain,
	}
	if studioCfg.TLSDir == "" {
		studioCfg.TLSDir = cfg.TLSDir
	}
	if studioCfg.EnrollToken == "" {
		studioCfg.EnrollToken = cfg.EnrollToken
	}
	go func() {
		if err := studiotransport.New(studioCfg, logger).Run(ctx); err != nil && ctx.Err() == nil {
			logger.Printf("skybridge-edge: studio gateway ended: %v", err)
		}
	}()
}
