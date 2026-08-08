# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## What this is

Skybridge is a Go data plane for **governed native database access**. An egress-only agent sits in
front of a database, speaks the native wire protocols (Postgres, MySQL, MongoDB), and masks PII in
result rows before they leave the network. `skybridge-edge` is the broader "single install" binary:
it also dials home to a Connector Gateway for read-only AWS/k8s tool dispatch, and can co-host the
wire proxy in the same process.

Skybridge is a standalone Go module with no required dependency on any specific control plane or
SaaS backend — clone it, `go build`, and run it against your own database. The default build has
zero optional-integration code compiled in. An optional Query Studio dispatch add-on lives behind
the `querystudio` Go build tag — see "Optional `querystudio` build tag" below — for anyone who wants
to wire skybridge-edge up to a query-execution dispatch backend of their own; it is not required to
use any part of the core wire proxy, masking pipeline, or tunnel/gateway relay.

## Commands

```sh
make build          # build all three binaries into bin/
make agent          # build cmd/skybridge-agent only
make gateway        # build cmd/skybridge-gateway only
make edge           # build cmd/skybridge-edge only (default: no Query Studio extras)
make edge-querystudio  # build cmd/skybridge-edge with Query Studio dispatch (-tags querystudio)
make test           # go test ./...
make test-querystudio  # go test -tags querystudio ./... (covers dbexec/dbquery/studiotransport)
make race           # go test -race ./...
make race-querystudio  # go test -race -tags querystudio ./...
make vet            # go vet ./...
make vet-querystudio   # go vet -tags querystudio ./...
make fmt            # go fmt ./...
make lint           # gofmt -l . check (what CI runs; fails on unformatted files)
make tidy           # go mod tidy
make gen            # regenerate gRPC stubs in internal/genpb (needs buf + protoc-gen-go[-grpc])
```

Run a single test:

```sh
go test ./internal/mask/... -run TestRemoteMasker_MaskRow
go test ./internal/wire/mysql/... -run TestAuth -v
```

The wire-proxy core (`internal/wire`, `internal/mask`, `internal/tunnel`, `internal/gateway`) is
**stdlib-only by design** — no third-party deps — so it builds and runs offline. The edge binary
additionally pulls in gRPC + aws-sdk-go-v2 and k8s client libs, but generated stubs are committed
under `internal/genpb` so `go build` still works without network access once modules are cached.

## Architecture

Three deployment shapes, one masking guarantee: the customer side is always **egress-only** (it
dials out; nothing dials in), and PII masking always happens in the agent process before bytes leave
the network.

- **Listener** — native clients connect straight to `skybridge-agent`.
- **Tunnel** — `skybridge-agent` dials out to `skybridge-gateway`; clients connect to the gateway,
  which relays already-masked bytes over the tunnel (`internal/tunnel` — a length-prefixed framed
  transport documented in `CONTRACT.md`).
- **Edge** — `skybridge-edge` dials out to a Connector Gateway (and optionally, with the
  `querystudio` build tag, a Query Studio gateway) and executes dispatched read-only tool calls
  locally (AWS reads, k8s reads); it can also co-host the wire proxy in the same process. This is
  the single binary most customers install.

### Layout

```
cmd/skybridge-agent      egress agent: listener OR tunnel mode
cmd/skybridge-gateway    relay gateway: agent endpoint + client listeners
cmd/skybridge-edge       unified edge: call-home transport(s) + AWS/k8s tool exec + optional wire proxy
internal/wire            wire engines: postgres, mysql, mongo, k8sapi — manual protocol parsing
internal/mask            masking pipeline: remote (Presidio) masker + path overlay + column overlay
internal/pathlabel       docpath (nested-document path walking) + label (path-scoped Store/Label types)
internal/tunnel          egress multiplexed transport (agent <-> gateway)
internal/gateway         agent registry + relay + optional control-plane session recording
internal/edge            edge tool dispatch: envelope, read-only policy, executor
internal/edge/awsexec    read-only AWS CLI / CloudWatch tool implementations
internal/edge/k8sexec    read-only kubectl-style tool implementation + policy
internal/edge/dbexec     [querystudio tag] db_query_{postgres,mysql,mongo} one-shot exec tools
internal/edge/dbquery    [querystudio tag] shared SQL/Mongo execute + PII masking for dbexec/studiotransport
internal/edge/transport  egress-only gRPC call-home client to the Connector Gateway
internal/edge/studiotransport  [querystudio tag] second egress-only gRPC dial to a Query Studio gateway
internal/edgeiam         edge enrollment / IAM helpers
internal/certstore       persists issued mTLS identity (local disk, optionally mirrored to AWS
                          Secrets Manager) so redeployed tasks skip re-enrollment
internal/wiremtls        mTLS enrollment for the agent<->gateway tunnel identity
internal/genpb           generated gRPC stubs (run `make gen` to refresh; committed so builds work offline)
internal/config          SKYBRIDGE_* environment config (see internal/config/config.go for the full list)
```

### The masking pipeline (`internal/mask`)

Every result row/document passes through a **chain of maskers**, all implementing
`mask.Masker.MaskRow`. A miss at any layer is not fatal — it falls through to the next layer, and an
unmasked value is never corrupted, only ever left as-is:

1. **`Remote`** (`internal/mask/remote.go`) — the only layer that inspects the value itself, not the
   field's name/path. Thin HTTP client for a Presidio-compatible `analyze`/`anonymize` service; this
   is what gives unstructured-text coverage. Best-effort: transport error, non-200, or zero detected
   spans fall through untouched (governed by `SKYBRIDGE_MASK_MODE`: `best-effort` vs `strict`).
2. **`PathOverlay`** — a `label.Store` lookup keyed on `(ObjectID, FieldPath)`, vendored from
   `internal/pathlabel`. Lets identically-named columns in different tables (`order.total` vs
   `user.total`) carry independent labels. Only `manual`/`platform`-sourced labels redact live; a
   detector-proposed label is inert until confirmed. Falls back to a bare-key lookup, then to layer 3.
   The MySQL wire engine and `dbquery`'s one-shot exec path resolve real per-row table/path identity;
   the Postgres and Mongo wire-proxy engines don't yet resolve table identity from the wire protocol,
   so those connections pass an empty `ObjectID` and skip straight to layer 3 (masking coverage there
   is unchanged from before this layer existed).
3. **`Overlay`** — the original flat, case-insensitive `column name -> replacement token` map
   (`SKYBRIDGE_PII_OVERLAY`, static or fetched/hot-swapped from the control plane via
   `SKYBRIDGE_PII_OVERLAY_URL`). No path awareness; kept as the last, most conservative layer.

### Wire boundaries (see `CONTRACT.md` for the full contracts)

- **Agent <-> Gateway tunnel** (`internal/tunnel`) — length-prefixed framed transport multiplexing
  many native-client sessions over one egress connection. Only already-masked bytes cross this
  boundary. Frame header is fixed 12 bytes, version-tagged; control messages are JSON discriminated
  by `kind` (`register`, `register_ack`, `heartbeat`).
- **Gateway -> Control plane** (optional) — HTTP session-lifecycle recording
  (default `/api/v1/sessions`), best-effort, and IP-allowlist admission checks before relaying a
  wire handshake (default `/api/v1/wire-admit`); both paths are overridable.
- **Agent -> Control plane credential exchange** (optional, `SKYBRIDGE_INJECT_CREDENTIALS=true`) —
  swaps a client-presented opaque session token for a freshly-minted upstream DB credential
  (`/native-access/proxy-exchange`). The agent originates its own upstream auth with the minted
  credential; the client never holds a credential the database would accept directly. Implemented for
  Postgres and MySQL; Mongo falls back to verbatim passthrough.

### Optional `querystudio` build tag

Query Studio dispatch is an optional add-on behind `//go:build querystudio`, excluded from the
default build/test/vet so the module has no required dependency on it:

- `internal/edge/studiotransport/` — second outbound dial to a Studio Gateway (`:7200`) for Query
  Studio dispatch.
- `internal/edge/dbexec/` + `internal/edge/dbquery/` — one-shot `db_query_{postgres,mysql,mongo}`
  execute path used by `POST /studio/exec`, sharing the PII masking pipeline with `studiotransport`.
- `internal/genpb/curlix/studiogateway/v1/` — generated gRPC stubs for the Studio Gateway protocol.
- `cmd/skybridge-edge/main_querystudio.go` (built with the tag) vs. `main_noquerystudio.go` (the
  default, no-op stub) implement `registerQueryStudioExtras`, the one hook `main.go` calls into.

Build/test with `make edge-querystudio` / `make test-querystudio` / `make vet-querystudio` (or
`-tags querystudio` directly). CI runs both the default and `-tags querystudio` legs so this surface
stays covered.

`internal/certstore/` (cross-redeploy mTLS identity persistence to AWS Secrets Manager via
`SKYBRIDGE_IDENTITY_SECRET_ARN` / `SKYBRIDGE_STUDIO_IDENTITY_SECRET_ARN` /
`SKYBRIDGE_WIRE_MTLS_IDENTITY_SECRET_ARN`) is generic infrastructure — used by both the core
wire-mTLS enrollment path and the edge transport — and is **not** behind the build tag.

## Configuration

All `SKYBRIDGE_*` environment variables are documented inline in `internal/config/config.go` and in
the README's Configure table — read those rather than guessing at a variable's default or behavior.
Switching `SKYBRIDGE_DB_TYPE` between `postgres`/`mysql`/`mongodb` is the primary axis; everything
else in config is protocol-agnostic.
