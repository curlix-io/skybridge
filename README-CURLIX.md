# skybridge-edge (Curlix vendored copy)

This directory is a **working copy** of [github.com/curlix-io/skybridge](https://github.com/curlix-io/skybridge) kept inside the Curlix monorepo so Studio Gateway convergence (`curlix.studiogateway.v1` on `:7200`) ships in the same PR as SaaS API/UI and connector Terraform.

## What changed here

- **`internal/edge/studiotransport/`** — second outbound dial to Studio Gateway (:7200) for Query Studio dispatch.
- **`internal/edge/dbexec/`** — `db_query_{postgres,mysql,mongo}` for `POST /studio/exec` (Design B).
- **`internal/edge/dbquery/`** — shared SQL/Mongo execute + PII masking for dbexec and studiotransport.
- **`internal/config/config.go`** — `SKYBRIDGE_STUDIO_*` env contract.
- **`cmd/skybridge-edge/main.go`** — runs connector transport and Studio transport concurrently when configured.
- **`internal/genpb/curlix/studiogateway/v1/`** — generated from `proto/curlix/studiogateway/v1/studio_gateway.proto`.
- **`internal/certstore/`** — persists the issued mTLS identity beyond local disk (optionally
  mirrored to AWS Secrets Manager via `SKYBRIDGE_IDENTITY_SECRET_ARN` /
  `SKYBRIDGE_STUDIO_IDENTITY_SECRET_ARN` / `SKYBRIDGE_WIRE_MTLS_IDENTITY_SECRET_ARN`), so an ECS
  task replaced by a redeploy recovers its already-issued cert instead of re-consuming the
  (already used) one-time enrollment token. Wired into
  `internal/edge/transport/material.go`, `internal/edge/studiotransport/material.go`, and
  `internal/wiremtls/enroll.go`. `integrations/curlix-connector/cloudformation/curlix-edge.yaml`
  provisions the backing secrets + IAM permissions.

## Sync upstream

1. Land changes here and run `go test ./...` from this directory.
2. Push equivalent commits to `curlix-io/skybridge` and tag a release (e.g. `v0.0.5`).
3. Bump `SKYBRIDGE_VERSION` in `integrations/curlix-connector/Dockerfile` and cut a connector image via **Release Connector** workflow.

## Regenerate protos

```bash
cd integrations/skybridge-edge
make genpb   # or: buf generate ../../proto --path curlix/studiogateway/v1/studio_gateway.proto
```

## Local test (Studio + connector)

Set both gateway pairs on one edge process:

```bash
export SKYBRIDGE_EDGE_GATEWAY=localhost:7100
export SKYBRIDGE_STUDIO_GATEWAY=localhost:7200
# … enrollment tokens, targets, CA bundle …
go run ./cmd/skybridge-edge
```
