# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## What this is

Skybridge is a Go data plane for **governed native database access**. An egress-only agent sits in
front of a database, speaks the native wire protocols (Postgres, MySQL, MongoDB), and masks PII in
result rows before they leave the network. `skybridge-edge` is the broader "single install" binary:
it also dials home to a Connector Gateway for AWS/k8s tool dispatch — AWS CLI calls are restricted to
a read-only allowlist, kubectl calls are policy-gated (interactive verbs and cluster-wide deletes
blocked, scoped mutations like `apply`/`patch`/a single-resource `delete` allowed) — and can co-host
the wire proxy in the same process.

Skybridge is a standalone Go module, independently open-sourced by Curlix, with no required
dependency on any specific control plane or SaaS backend — clone it, `go build`, and run it against
your own database. The default build has zero optional-integration code compiled in. An optional
Query Studio dispatch add-on lives behind the `querystudio` Go build tag — see
[Optional `querystudio` build tag](#optional-querystudio-build-tag) below — for anyone who wants to
wire skybridge-edge up to a query-execution dispatch backend of their own; it is not required to use
any part of the core wire proxy, masking pipeline, or tunnel/gateway relay.

---

## Setup

```sh
go build ./...        # needs only Go >= 1.26 for the default build (stdlib-only core)
```

No editable installs, no `npm ci`, no service containers required to build or run unit tests. The
`deploy/docker-compose.yml` stack (Presidio analyzer/anonymizer + the agent) is only needed to
exercise the `Remote` content-detection masking layer end to end — see
[Quick start](./README.md#quick-start) in the README.

---

## Commands

```sh
make build             # build all three binaries into bin/
make agent             # build cmd/skybridge-agent only
make gateway           # build cmd/skybridge-gateway only
make edge              # build cmd/skybridge-edge only (default: no Query Studio extras)
make edge-querystudio  # build cmd/skybridge-edge with Query Studio dispatch (-tags querystudio)
make labeller          # build cmd/skybridge-labeller only (opt-in, not part of `make build`)
make test              # go test ./...
make test-querystudio  # go test -tags querystudio ./... (covers dbexec/dbquery/studiotransport)
make race              # go test -race ./...
make race-querystudio  # go test -race -tags querystudio ./...
make vet               # go vet ./...
make vet-querystudio   # go vet -tags querystudio ./...
make fmt               # go fmt ./...
make lint              # gofmt -l . check (what CI runs; fails on unformatted files)
make tidy              # go mod tidy
make gen               # regenerate gRPC stubs in internal/genpb (needs buf + protoc-gen-go[-grpc])
```

Run a single test:

```sh
go test ./internal/mask/... -run TestRemoteMasker_MaskRow
go test ./internal/wire/mysql/... -run TestAuth -v
go test -tags querystudio ./internal/edge/dbquery/... -run TestMaskRows -v
```

**Run before pushing:** `make lint && make vet && go test -race ./...` — and the querystudio legs
(`make vet-querystudio && go test -race -tags querystudio ./...`) if you touched anything under a
`querystudio`-gated package (see the layout table below) or `internal/certstore`. CI (`.github/workflows/ci.yml`)
runs exactly these two legs; there's no local `make verify` alias for the combination, so run them
by hand.

The wire-proxy core (`internal/wire`, `internal/mask`, `internal/tunnel`, `internal/gateway`) is
**stdlib-only by design** — no third-party deps — so it builds and runs offline. The edge binary
additionally pulls in gRPC + aws-sdk-go-v2 and k8s client libs, but generated stubs are committed
under `internal/genpb` so `go build` still works without network access once modules are cached.

---

## Architecture

Three deployment shapes, one masking guarantee: the customer side is always **egress-only** (it
dials out; nothing dials in), and PII masking always happens in the agent process before bytes leave
the network.

- **Listener** — native clients connect straight to `skybridge-agent`.
- **Tunnel** — `skybridge-agent` dials out to `skybridge-gateway`; clients connect to the gateway,
  which relays already-masked bytes over the tunnel (`internal/tunnel` — a length-prefixed framed
  transport documented in `CONTRACT.md`).
- **Edge** — `skybridge-edge` dials out to a Connector Gateway (and optionally, with the
  `querystudio` build tag, a Query Studio gateway) and executes dispatched AWS/k8s tool calls
  locally, gated by the policies in `internal/edge/policy.go` and `internal/edge/k8sexec/policy.go`
  (see the Layout table below for exactly what each allows); it can also co-host the wire proxy in
  the same process. This is the single binary most customers install.

### Layout

```
cmd/skybridge-agent      egress agent: listener OR tunnel mode
cmd/skybridge-gateway    relay gateway: agent endpoint + client listeners
cmd/skybridge-edge       unified edge: call-home transport(s) + AWS/k8s tool exec + optional wire proxy
cmd/skybridge-labeller   periodic AI-based path-label scan job (see docs/AI_PATH_LABELLING_DESIGN.md);
                         opt-in, not part of `make build` — build/run it explicitly via `make labeller`
internal/wire            wire engines: postgres, mysql, mongo, k8sapi — manual protocol parsing
internal/mask            masking pipeline: remote (Presidio) masker + path overlay + column overlay;
                         Column.TypeKind lets PathOverlay redact a confirmed label on a typed
                         (non-free-text) column with a type-valid placeholder instead of skipping
                         it — see docs/PATH_LABEL_IDENTITY_GAPS_DESIGN.md
internal/mask/metrics    masking-outcome metrics (counts only, never values) synced to the control plane
internal/pathlabel       docpath (nested-document path walking) + label (path-scoped Store/Label types)
internal/pathlabel/remotestore  label.Store backed by the control plane's pii-path-labels pull/push API
internal/pathlabel/aiclassifier  AI-based path labeller: Classifier/Scanner interfaces + an
                         LLM-API-backed implementation, proposing SourceProposed labels independent
                         of live query traffic — see docs/AI_PATH_LABELLING_DESIGN.md
internal/pathlabel/sqlsampler    database/sql-based aiclassifier.Sampler for Postgres/MySQL, used by
                         cmd/skybridge-labeller
internal/labeller        cmd/skybridge-labeller's run loop: validates config, wires
                         aiclassifier.Scanner + sqlsampler.Sampler + remotestore.Store together
internal/tunnel          egress multiplexed transport (agent <-> gateway)
internal/gateway         agent registry + relay + optional control-plane session recording
internal/edge            edge tool dispatch: envelope, policy, executor
internal/edge/awsexec    read-only-allowlisted AWS CLI / CloudWatch tool implementations
internal/edge/k8sexec    policy-gated kubectl tool implementation — allowlists read-only verbs only
                         (get/describe/logs/top/explain/version/api-resources/api-versions); every
                         other verb, including apply/patch/create/delete/scale/label/cordon/drain
                         and the always-blocked interactive verbs (exec/attach/cp/port-forward), is
                         rejected before exec.CommandContext runs it
internal/edge/dbexec     [querystudio tag] db_query_{postgres,mysql,mongo,snowflake} one-shot
                         read-only exec tools (EnforceReadOnly:true, never overridden) plus
                         db_execute_write, a distinct write-capable tool gated by Curlix's own
                         allow/deny decision made before dispatch, not by any local keyword/statement
                         classification here — see dbquery.Options.Write's doc comment
internal/edge/dbquery    [querystudio tag] shared SQL/Mongo execute + PII masking for dbexec/studiotransport;
                         Options.Write routes to a separate ExecContext/CRUD write path (write.go),
                         mutually exclusive with EnforceReadOnly
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
   is what gives unstructured-text coverage. Supports org-supplied custom recognizers
   (`internal/config/recognizers.go`, `SKYBRIDGE_MASK_RECOGNIZERS_YAML`/`_FILE`, or dynamically via
   `SKYBRIDGE_PII_RECOGNIZERS_URL` — `internal/agent/recognizers_source.go`) passed through
   verbatim as Presidio's `ad_hoc_recognizers`. Best-effort: transport error, non-200, or zero
   detected spans fall through untouched (governed by `SKYBRIDGE_MASK_MODE`: `best-effort` vs
   `strict`).
2. **`PathOverlay`** (`internal/mask/pathoverlay.go`) — a `label.Store` lookup keyed on `(ObjectID,
   FieldPath)`, vendored from `internal/pathlabel`. Lets identically-named columns in different
   tables (`order.total` vs `user.total`) carry independent labels. Only `manual`/`platform`-sourced
   labels redact live; a detector-proposed label is inert until confirmed. Falls back to a bare-key
   lookup, then to layer 3. Live in the agent's chain only when `SKYBRIDGE_PATH_LABEL_URL` is set
   (`internal/agent/agent.go`'s `buildMaskerWithOverlay` wires it against
   `internal/pathlabel/remotestore.Store`, which pulls confirmed labels and pushes detector-proposed
   ones over that URL) — an unconfigured deployment gets `mask.Noop{}` in that slot, never a
   permanently-missing lookup. All three wire engines and `dbquery`'s one-shot exec path resolve
   real per-row table/path identity: MySQL from its column-definition packets, Mongo by correlating
   each request's collection with its reply via the wire protocol's `requestID`/`responseTo` fields
   (see `internal/wire/mongo` package doc), and Postgres via a dedicated `pg_class`/`pg_namespace`
   lookup connection the agent owns (only a numeric table OID is on the wire, not a name) — but only
   when `SKYBRIDGE_POSTGRES_CATALOG_DSN` is set (see REDACTION.md's "Postgres table-identity
   resolution"); unconfigured, Postgres connections pass an empty `ObjectID` and skip straight to
   layer 3, same as always.
3. **`Overlay`** (`internal/mask/overlay.go`) — the original flat, case-insensitive `column name ->
   replacement token` map (`SKYBRIDGE_PII_OVERLAY`, static or fetched/hot-swapped from the control
   plane via `SKYBRIDGE_PII_OVERLAY_URL`). No path awareness; kept as the last, most conservative
   layer.

`internal/mask/metrics` buffers pure-metadata masking-outcome counts (entity type, source layer,
connection — never masked or raw values) and flushes them to the control plane
(`SKYBRIDGE_MASKING_METRICS_URL`) so dashboards can show "how much PII did we mask, of what type" without
the SaaS backend ever seeing a value. Structurally mirrors `remotestore`: bounded in-memory pending
set, periodic push, flush-on-shutdown.

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
  Postgres, MySQL, and Mongo (Mongo requires the client to be configured with
  `authMechanism=PLAIN`, since a driver will not auto-discover it — real MongoDB servers never
  advertise `PLAIN` via `hello`).
- **Agent -> Control plane, pathlabel + recognizers + metrics** (all optional) — three independent
  pull/push HTTP loops layered on top of the same poll pattern as the flat overlay
  (`internal/agent/overlay_source.go`): `internal/pathlabel/remotestore` (pull confirmed labels,
  push proposed ones), `internal/agent/recognizers_source.go` (pull custom Presidio recognizers),
  `internal/mask/metrics` (push masking-outcome counts). None of these block a live database
  session; a sync failure just leaves the last-known state in place.

### Optional `querystudio` build tag

Query Studio dispatch is an optional add-on behind `//go:build querystudio`, excluded from the
default build/test/vet so the module has no required dependency on it:

- `internal/edge/studiotransport/` — second outbound dial to a Studio Gateway (`:7200`) for Query
  Studio dispatch.
- `internal/edge/dbexec/` + `internal/edge/dbquery/` — one-shot `db_query_{postgres,mysql,mongo,snowflake}`
  read-only execute path used by `POST /studio/exec`, sharing the PII masking pipeline with
  `studiotransport`, plus `db_execute_write` — a separate write-capable tool (Postgres/MySQL via
  `ExecContext`, Mongo via direct insert/update/delete/replace/aggregate calls) that runs a
  dispatched statement exactly as given. Whether a given statement should have been dispatched at
  all is Curlix's own allow/deny decision made before dispatch, not something the edge re-derives by
  inspecting the statement — the read-only `db_query_*` tools' `EnforceReadOnly: true` is untouched
  and permanent regardless of this tool's existence.
- `internal/genpb/curlix/studiogateway/v1/` — generated gRPC stubs for the Studio Gateway protocol.
- `cmd/skybridge-edge/main_querystudio.go` (built with the tag) vs. `main_noquerystudio.go` (the
  default, no-op stub) implement `registerQueryStudioExtras`, the one hook `main.go` calls into.

Database support at a glance — which databases get a transparent wire-proxy engine (native client,
no query rewriting) vs. one-shot exec-only support (behind the `querystudio` tag):

| Database  | Wire protocol      | `internal/wire` engine | `dbquery`/`dbexec` (querystudio) | Notes |
|-----------|---------------------|:-----------------------:|:---------------------------------:|-------|
| Postgres  | native TCP          | ✅ `internal/wire/postgres` | ✅ | Resolves real per-row table/path identity for `PathOverlay` via a dedicated `pg_class` lookup connection, when `SKYBRIDGE_POSTGRES_CATALOG_DSN` is set (falls back to layer-3-only otherwise — no name on the wire itself, only a numeric OID). |
| MySQL     | native TCP          | ✅ `internal/wire/mysql`    | ✅ | Resolves real per-row table/path identity for `PathOverlay` from column-definition packets. |
| MongoDB   | native TCP (BSON)   | ✅ `internal/wire/mongo`    | ✅ | Resolves real per-reply collection/path identity for `PathOverlay` by correlating each request with its reply. |
| Snowflake | HTTPS/REST          | ❌ (no wire protocol to proxy) | ✅ (`querystudio` only) | `database/sql` + `gosnowflake`; one-shot exec is the whole integration, not a placeholder for a future wire engine. |

Build/test with `make edge-querystudio` / `make test-querystudio` / `make vet-querystudio` (or
`-tags querystudio` directly). CI runs both the default and `-tags querystudio` legs
(`.github/workflows/ci.yml`'s `build-test` and `build-test-querystudio` jobs) so this surface stays
covered — a package added under the tag is silently unbuilt/unvetted/untested by the default job
alone, so any new `querystudio`-gated code must be exercised by that second job, not just built
locally with the tag.

`internal/certstore/` (cross-redeploy mTLS identity persistence to AWS Secrets Manager via
`SKYBRIDGE_IDENTITY_SECRET_ARN` / `SKYBRIDGE_STUDIO_IDENTITY_SECRET_ARN` /
`SKYBRIDGE_WIRE_MTLS_IDENTITY_SECRET_ARN`) is generic infrastructure — used by both the core
wire-mTLS enrollment path and the edge transport — and is **not** behind the build tag.

---

## Security model

> Masking always happens in the agent process, before bytes leave the network — there is no
> "redact after the fact" step and no reliance on the client, the network, or a downstream proxy to
> enforce anything.

### Fallthrough, never corrupt
A miss at any masking layer falls through to the next layer unchanged; an unmasked value is never
corrupted, only ever left as-is (`internal/mask/mask.go`'s `Masker` contract). Anything a wire
engine can't parse is forwarded **unmasked, never corrupted** — the design deliberately favors "some
real risk of unmasked data on an edge case the parser doesn't understand yet" over "silently corrupt
the client's data." Adding a new masking layer must never change this contract for the layers
already in production — see `REDACTION.md`'s note on `PathOverlay` being layered on top of two
already-live layers without altering either one's behavior.

### Secrets and PII
- **Never** log a raw masked/unmasked value, a session token, or a minted database credential.
  `internal/mask/metrics` and `internal/pathlabel/remotestore` exist specifically to sync
  *metadata* (counts, entity types, field paths) without ever transmitting the value itself —
  follow that pattern for any new telemetry.
- The minted upstream credential from credential exchange (`CONTRACT.md` §3) exists in clear only
  in that one HTTP response and is never sent to the native client.
- `SKYBRIDGE_MASK_MODE=strict` aborts the row/connection on a masker failure instead of falling
  through unmasked — use it wherever "the query fails" is preferable to "silently pass through raw
  PII during an outage."

### Credential handoff
With `SKYBRIDGE_INJECT_CREDENTIALS=true`, the client presents an opaque session token as its
password; the agent terminates that login locally, exchanges the token with the control plane for a
freshly-minted upstream credential, and originates its own upstream auth. The client therefore never
holds a credential the database would accept directly. Implemented for Postgres and MySQL; Mongo
falls back to verbatim passthrough (logged at startup, not silent).

### Code review checklist (security)
- [ ] A new masking layer falls through on miss/error — never corrupts, never blocks a query unless
  `SKYBRIDGE_MASK_MODE=strict` is explicitly in play
- [ ] No raw PII value, token, or minted credential in a log line, error message, or metrics payload
- [ ] Any new control-plane HTTP call (pull or push) is best-effort from the data plane's
  perspective — a reporting/sync failure must never break or delay a live database session
- [ ] New wire-protocol parsing forwards unparseable input unmasked rather than guessing at
  structure or corrupting bytes
- [ ] `CONTRACT.md` updated if a wire/HTTP boundary's shape changed (see below)

---

## Testing contracts

### What to run
- **Unit tests** — `go test ./...` (default build) and, if you touched a `querystudio`-gated
  package or `internal/certstore`, `go test -tags querystudio ./...`. Most packages have no
  external-service dependency; a handful (`internal/edge/transport`, `internal/wiremtls`,
  `internal/gateway`) spin up an in-process TLS listener or hermetic HTTP test server rather than
  reaching a real network service — keep new tests hermetic the same way rather than reaching for
  Docker.
- **Race detector** — `go test -race ./...` before pushing anything touching `internal/tunnel`,
  `internal/gateway`, or the sync loops in `internal/agent`/`internal/mask/metrics`/
  `internal/pathlabel/remotestore` — all of these run background goroutines against shared state.
- **CI** mirrors this exactly: `.github/workflows/ci.yml` runs `gofmt -l .`, `go vet`, `make build`,
  and `go test -race -coverprofile=... ./...` on the default build, then the same three steps again
  with `-tags querystudio`.

### Test naming
`Test<Subject>_<Condition>`, e.g. `TestRemoteMasker_MaskRow`, `TestChainAppliesInOrder`,
`TestOverlaySkipsNullAndBinary` — see `internal/mask/mask_test.go` for the convention across a
single file.

### Bug fixes
Include a regression test that fails before the fix and passes after — proves the fix actually
fixes the reported failure, not just plausible-looking code.

### Contract changes
Any change to the tunnel frame format, a control-message shape, or an HTTP request/response body
documented in `CONTRACT.md` needs: (1) `CONTRACT.md` updated in the same PR, (2) a round-trip test
(see `internal/tunnel/session_test.go`'s `TestFrameRoundTrip`/`TestOpenMetaRoundTrip` for the
pattern), (3) a compatibility note if the change isn't additive — receivers already reject unknown
frame versions, so a breaking change here is not backward compatible by default.

---

## Configuration

All `SKYBRIDGE_*` environment variables are documented inline in `internal/config/config.go` and in
the README's Configure table — read those rather than guessing at a variable's default or behavior.
Switching `SKYBRIDGE_DB_TYPE` between `postgres`/`mysql`/`mongodb` is the primary axis; everything
else in config is protocol-agnostic. New optional pull/push integrations follow the same shape every
time — a base URL env var, a bearer token defaulting to `SKYBRIDGE_TOKEN`, and a poll/push interval
with a floor (`internal/agent/overlay_source.go`, `internal/agent/recognizers_source.go`,
`internal/pathlabel/remotestore`, `internal/mask/metrics` are all instances of this pattern); follow
it rather than inventing a new config shape for the next one.

---

## Docs stay in sync

Any change to a wire/HTTP contract, an `SKYBRIDGE_*` env var, the masking chain's layer order, or the
`querystudio` build-tag surface must update every doc that describes it in the same PR — a stale doc
here is actively misleading since this repo (unlike a typical monorepo) *is* the external-facing
documentation for anyone standing Skybridge up against their own database:

| Change | Update |
|---|---|
| Tunnel frame format, control message, or either HTTP contract body | `CONTRACT.md` |
| New/changed `SKYBRIDGE_*` env var | `internal/config/config.go` doc comment + README's Configure table |
| Masking chain layer order, fallthrough behavior, or what's live vs. groundwork | `REDACTION.md` + README's "How masking works" section |
| `querystudio`-gated package added/moved | This file's Layout table + `.github/workflows/ci.yml` if a new CI leg is needed |
| Anything demoed in `examples/demo/` | Re-record `redaction-demo.gif`/`.cast` if the actual output changed (see `REDACTION.md`'s "See it work" section for the capture recipe) |

---

## Where to look next

| Need | Location |
|------|----------|
| Masking pipeline deep dive (with live demo GIF) | `REDACTION.md` |
| How our redaction compares to hoop.dev/OSS DLP projects, improvement backlog | `docs/REDACTION_COMPETITIVE_ANALYSIS.md` |
| Wire/HTTP contract reference | `CONTRACT.md` |
| Quick start, all `SKYBRIDGE_*` vars, edge binary details | `README.md` |
| Full env var list with defaults/behavior | `internal/config/config.go` |
| CI pipeline (both build legs) | `.github/workflows/ci.yml` |
| Local Presidio + agent demo stack | `deploy/docker-compose.yml`, `examples/demo/run-demo.sh` |

---

## Two cross-cutting behavioral rules

1. **Fallthrough over corruption, always.** Every masking layer and every wire-protocol parser must
   leave an unhandled value exactly as it was rather than guess, drop, or partially transform it.
   This applies to new code the same way it applies to the three existing layers — see
   [Security model](#security-model) above.

2. **Sync docs and CI with contract changes in the same pass.** A `CONTRACT.md`/config/README
   change without the corresponding CI leg or doc update ships a boundary that only half the repo
   knows about — see [Docs stay in sync](#docs-stay-in-sync) above.
