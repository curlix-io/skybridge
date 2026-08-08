# Skybridge

**Skybridge** is a small Go data plane for **governed native database access**. An egress-only agent
sits in front of your database, speaks the native client protocols (`psql`, `mysql`, `mongosh`, app
drivers), and **masks PII at the source** — so raw rows never leave your network.

- Stdlib-only wire-proxy core — manual protocol parsing + masking, no third-party deps.
- Content-aware masking — pluggable remote masker + a column overlay you define.
- Anything an engine can't parse is forwarded **unmasked, never corrupted**.
- One edge binary (`skybridge-edge`) also dials home for **live read-only AWS reads**, so everything
  that must run inside your network is a single install.

**Jump to:** [How it works](#how-it-works) · [Quick start](#quick-start) ·
[How masking works](#how-masking-works) · [Configure](#configure) ·
[The `skybridge-edge` binary](#the-skybridge-edge-binary) · [Layout](#layout) ·
[REDACTION.md](./REDACTION.md) (deep dive, with a live demo GIF)

## How it works

```mermaid
flowchart LR
    subgraph clients["Native DB clients"]
        c1["psql / mysql / mongosh"]
    end

    subgraph net["Your network (egress-only)"]
        agent["Skybridge agent<br/>masks PII here"]
        edge["Skybridge edge<br/>call-home + AWS reads"]
        db[(Database)]
        aws["AWS account<br/>(read-only)"]
        agent --> db
        edge --> aws
    end

    subgraph saas["Control plane (SaaS)"]
        gw["Skybridge gateway"]
        cg["Connector Gateway"]
    end

    c1 -->|"listener mode"| agent
    c1 -->|"tunnel mode"| gw
    gw -. "egress tunnel<br/>(masked bytes only)" .-> agent
    cg -. "egress call-home<br/>(read-only tool calls)" .-> edge
```

Skybridge ships three deployment shapes; all of them keep the customer side **egress-only** (it
dials out, nothing dials in):

- **Listener** — native clients connect straight to the agent. Simplest setup.
- **Tunnel** — the agent dials **out** to a gateway; clients connect to the gateway, which relays
  already-masked bytes over the tunnel. Masking still happens at the agent.
- **Edge** — `skybridge-edge` dials **out** to a Connector Gateway and runs dispatched
  **read-only tool calls** locally — chiefly live AWS reads against your account — and can co-host the
  wire proxy in the same process. One install for everything that must run inside your network. See
  [The `skybridge-edge` binary](#the-skybridge-edge-binary) below.

## Quick start

Put the agent in front of your database and point a native client at it.

### Fastest path: column redaction, no external services

Needs only Go ≥ 1.26 — no Docker, no Presidio, no network calls. This uses the column-name
`Overlay` layer only (see [How masking works](#how-masking-works)); it won't catch PII embedded in
free text, but it's the quickest way to see redaction working end to end.

```sh
SKYBRIDGE_UPSTREAM=db.internal:5432 \
SKYBRIDGE_PII_OVERLAY_FILE=./examples/pii-overlay.yaml \
go run ./cmd/skybridge-agent
```

[`examples/pii-overlay.yaml`](./examples/pii-overlay.yaml) is a column → replacement-token map in
YAML (or JSON — both parse the same way); copy it, add your own columns, and point
`SKYBRIDGE_PII_OVERLAY_FILE` at your copy. A file is easier to author, diff, and commit than the
one-line inline alternative, `SKYBRIDGE_PII_OVERLAY='{"email":"[redacted]","ssn":"[redacted]"}'`
(still supported; the file wins if both are set).

Then connect a native client through the agent (listening on `:15432` by default):

```sh
psql "postgres://user:pass@localhost:15432/appdb"
```

### Full path: add content-detection masking (catches PII in free text too)

The column overlay above only matches by column *name*. To also catch PII-shaped values wherever
they appear — free-text notes, JSON blobs, unlisted columns — layer on the `Remote` masker, a thin
client for any Presidio-compatible `analyze`/`anonymize` service. The bundled Docker Compose setup
brings up Microsoft Presidio's analyzer + anonymizer alongside the agent, per
[hoop.dev's Presidio deployment guide](https://hoop.dev/docs/setup/deployment/presidio):

```sh
cd deploy
SKYBRIDGE_UPSTREAM=db.internal:5432 docker compose up
```

That's it — result rows are masked before they reach the client, using Presidio's NER-based PII
detection, plus any `SKYBRIDGE_PII_OVERLAY`/`SKYBRIDGE_PII_OVERLAY_FILE` rules you set via the
compose file's env vars. Set `SKYBRIDGE_MASK_ANALYZE_URL`/`SKYBRIDGE_MASK_ANONYMIZE_URL` to empty to
disable content masking (governed passthrough), or point them at a different `analyze`/`anonymize`
service. Running with plain `go run` (no compose) has no mask URLs by default — set them explicitly
to reach a Presidio instance you run yourself.

## How masking works

> For a deeper dive — including a live demo GIF, the anonymizer-strategy config, and exactly what's
> live vs. groundwork in the path-scoped labels layer — see [REDACTION.md](./REDACTION.md).

Every result row/document passes through a **chain of maskers**, each implementing the same
interface (`mask.Masker.MaskRow`, in `internal/mask/mask.go`). A miss at any layer is not fatal —
the value falls through to the next layer, and an unmasked value is *never* corrupted, only ever
left as-is. The chain runs in this order:

```mermaid
flowchart TD
    row["Result row / document<br/>(from Postgres, MySQL, or Mongo)"]

    row --> remote

    subgraph remote["1. Remote — content-shape detection (Presidio-compatible)"]
        direction TB
        r1["POST /analyze<br/>(text, language) → detected PII spans"]
        r2["POST /anonymize<br/>(text, spans) → redacted text"]
        r1 --> r2
    end

    remote --> overlay

    subgraph overlay["2. Overlay — flat column-name map"]
        direction TB
        o1["column name (case-insensitive) → replacement token<br/>e.g. email → [redacted]"]
    end

    overlay --> out["Masked row/document<br/>→ forwarded to the client"]
```

**Layer 1 — `Remote` (content-shape detection, structured *and* unstructured alike).** This is the
only layer that inspects the *value itself* rather than the field's name/path, which is what makes
it work uniformly on structured columns (a `VARCHAR` that happens to contain an email) and on
unstructured/free-text fields (a notes blob, a JSON string column) alike — it has no notion of
schema, only "is this string PII-shaped." It's a thin HTTP client for any service that implements
[Presidio](https://github.com/data-privacy-stack/presidio)'s two-call shape:

1. `POST {analyzeURL}` with `{text, language}` → a list of detected entity spans (`entity_type`,
   `start`, `end`, `score`).
2. `POST {anonymizeURL}` with `{text, analyzer_results, anonymizers}` → the redacted text (this repo
   always requests the `replace` anonymizer with `new_value: "[redacted]"`).

Configured via `SKYBRIDGE_MASK_ANALYZE_URL` / `SKYBRIDGE_MASK_ANONYMIZE_URL` (both required
together — see [Configure](#configure)); values shorter than `MinLen` (default 4 bytes) skip the
call entirely, since numbers/short codes are rarely worth a round trip. Best-effort throughout: a
transport error, non-200, or zero detected spans all fall through with the value untouched — see
`internal/mask/remote.go`.

**Layer 2 — `Overlay` (flat column-name map).** A case-insensitive `column name → replacement
token` map (`SKYBRIDGE_PII_OVERLAY`, or fetched dynamically from the control plane via
`SKYBRIDGE_PII_OVERLAY_URL` — see
[Dynamic PII overlay](#dynamic-pii-overlay-fetched-from-your-control-plane)). No path awareness: `total`
under `order` and `total` under `user` share one rule.

### Path-scoped labels (`internal/pathlabel`, `mask.PathOverlay`) — groundwork, not yet in the live chain

`internal/pathlabel` and `mask.PathOverlay`
(`internal/mask/pathoverlay.go`) exist in this repo but are **not yet wired into the two layers
above** — `buildMaskerWithOverlay` in `internal/agent/agent.go` doesn't include a `PathOverlay` in
its chain, since doing so needs a real, populated `label.Store` to be anything but a permanent miss
(an empty store is dead weight, and it would also break the "nothing configured → transparent
passthrough" guarantee other code relies on).

What *is* live today: `mask.Column` carries `ObjectID`/`Path` fields, and `internal/edge/dbquery`'s
one-shot exec path (`internal/edge/dbquery/mask.go`) populates them for every query — it resolves
per-query table/collection identity (`"{org}:{driver}:{database}:{table}"`) and walks Mongo
documents *nested* rather than flattened first (`internal/pathlabel/docpath`), so a `profile.contact.email`
leaf is addressable independently of a top-level `email` column. The MySQL wire-proxy engine also
parses real per-column table identity off the wire (schema + `org_table` from the column-definition
packet). This is groundwork for a future `PathOverlay` layer that can distinguish `order.total` from
`user.total` — something a bare key-name rule can never express — but until a backing store exists,
`Column.ObjectID`/`Path` are populated and otherwise unused by the two layers above.

**Structured vs. unstructured, in one sentence:** layer 1 (`Remote`) is what actually gives you
unstructured-text coverage (it doesn't care what the field is called or where it sits in a
document); layer 2 (`Overlay`) is a structured-schema shortcut — a cheap, exact-match lookup by
column name — that skips the network round trip for fields a human has already labelled. Both
layers run on **every** row/document by default; there's no separate "structured mode" vs.
"unstructured mode" to configure.

### Redaction in action: SQL rows, JSON, BSON, and free text

Same masking chain, four shapes of data. Left is what the database returns; right is what the
client actually receives.

**A SQL row (column overlay — matches by column name, no external service needed):**

```
 id |         email          | ssn                          id |       email       |     ssn
----+-------------------------+-----                →      ----+-------------------+-------------
 42 | alice@example.com      | 123-45-6789                 42 | [redacted]        | [redacted]
```

**A free-text column (content detection — `Remote`/Presidio catches PII regardless of column name):**

```
notes: "Called customer, callback number is 555-867-5309, said email jane@doe.com bounced"
   →
notes: "Called customer, callback number is [redacted], said email [redacted] bounced"
```

**A JSON blob stored in a text column (`Remote` inspects the value itself, so it doesn't care that
it's JSON rather than prose):**

```
payload: '{"name":"Jane Doe","contact":"jane@doe.com"}'
   →
payload: '{"name":"Jane Doe","contact":"[redacted]"}'
```

**A nested Mongo/BSON document (path-scoped labels — lets `order.total` and `user.total` carry
independent rules despite sharing a field name; see `PathOverlay` above, currently wired into the
`dbquery` one-shot exec path, not yet the live Postgres/Mongo wire-proxy):**

```
{ "profile": { "email": "jane@doe.com", "name": "Jane" }, "order": { "total": 42 } }
   →
{ "profile": { "email": "[redacted]", "name": "Jane" }, "order": { "total": 42 } }
```

Only `profile.email` is redacted — `order.total` and `profile.name` carry no label, so they fall
through every layer untouched, exactly as the fallthrough-on-miss contract guarantees.

## Configure

Set these as environment variables (full list in `internal/config/config.go`):

| Variable | Default | What it does |
|---|---|---|
| `SKYBRIDGE_UPSTREAM` | — | upstream database `host:port` (**required**) |
| `SKYBRIDGE_DB_TYPE` | `postgres` | `postgres`, `mysql`, or `mongodb` |
| `SKYBRIDGE_LISTEN` | `:15432` / `:13306` / `:27018` | local address clients connect to |
| `SKYBRIDGE_PII_OVERLAY` | — | JSON `{ "column": "[redacted]" }` map you define (static) |
| `SKYBRIDGE_PII_OVERLAY_FILE` | — | path to a YAML or JSON file with the same column->token map (see [`examples/pii-overlay.yaml`](./examples/pii-overlay.yaml)) — easier to author/diff/commit than inline JSON; takes priority over `SKYBRIDGE_PII_OVERLAY` when both are set, falling back to it if the file is missing/invalid |
| `SKYBRIDGE_PII_OVERLAY_URL` | — | control-plane endpoint to fetch the org's projected overlay (`GET /your-control-plane/pii-overlay`); enables dynamic, hot-swapped masking |
| `SKYBRIDGE_PII_OVERLAY_TOKEN` | `SKYBRIDGE_TOKEN` | bearer token for the overlay fetch |
| `SKYBRIDGE_PII_OVERLAY_POLL_SECONDS` | `60` | overlay refresh interval (min 15s; `-1` = fetch once at startup) |
| `SKYBRIDGE_MASK_ANALYZE_URL` | — (`http://presidio-analyzer:3000/analyze` under `deploy/docker-compose.yml`) | enable content masking: any `POST /analyze` service — Microsoft Presidio by default |
| `SKYBRIDGE_MASK_ANONYMIZE_URL` | — (`http://presidio-anonymizer:3000/anonymize` under compose) | …paired `POST /anonymize` service |
| `SKYBRIDGE_MASK_LANGUAGE` | `en` | language passed to the analyzer |
| `SKYBRIDGE_MASK_ENTITIES` | — (low-cost regex set: `EMAIL_ADDRESS,PHONE_NUMBER,CREDIT_CARD,US_SSN,IP_ADDRESS,IBAN_CODE,CRYPTO`) | comma-separated Presidio entity types to detect; NER-backed types (`PERSON`, `LOCATION`, `ORGANIZATION`, `NRP`) are opt-in — they run full spaCy inference per value and are prone to false positives on ordinary business data |
| `SKYBRIDGE_MASK_ANONYMIZERS` | — (blanket `{"DEFAULT":{"type":"replace","new_value":"[redacted]"}}`) | JSON Presidio "anonymizers" object, one strategy per entity type — e.g. partial-mask an SSN instead of a flat replace |
| `SKYBRIDGE_MASK_MODE` | `best-effort` | `best-effort` forwards a value unmasked if the remote masker errors/is unreachable (a masker outage never blocks a query); `strict` aborts the row/connection instead so unmasked content never reaches the client (mirrors hoop.dev's `DLP_MODE`) |
| `SKYBRIDGE_INJECT_CREDENTIALS` | `false` | enable credential handoff (clients present an opaque session token, not a DB password) |
| `SKYBRIDGE_CREDENTIAL_EXCHANGE_URL` | — | control-plane endpoint that swaps a session token for an upstream credential (`POST /your-control-plane/proxy-exchange`) |
| `SKYBRIDGE_CREDENTIAL_EXCHANGE_TOKEN` | `SKYBRIDGE_TOKEN` | bearer for the exchange call |
| `SKYBRIDGE_CLIENT_TLS_CERT_FILE` / `_PEM` | — | server cert (Postgres) — enables terminating client TLS so the token isn't sent in cleartext |
| `SKYBRIDGE_CLIENT_TLS_KEY_FILE` / `_PEM` | — | matching private key |
| `SKYBRIDGE_CLIENT_TLS_SELF_SIGNED` | `false` | dev: generate an ephemeral self-signed cert at startup (clients use `sslmode=require`) |
| `SKYBRIDGE_UPSTREAM_TLS` | `disable` | agent→database TLS (Postgres / MySQL / Mongo): `disable` \| `prefer` \| `require` \| `verify-ca` \| `verify-full` |
| `SKYBRIDGE_UPSTREAM_TLS_CA_FILE` / `_PEM` | system roots | trust roots used by `verify-ca` / `verify-full` (e.g. the RDS CA bundle) |
| `SKYBRIDGE_UPSTREAM_TLS_SERVER_NAME` | dial host | override the verified hostname / SNI sent to the upstream |

Switch databases by changing `SKYBRIDGE_DB_TYPE`; everything else is identical.

### Credential handoff (the client never holds a database password)

By default the agent forwards the client's authentication to the database verbatim, so the native
client presents a real database credential. With **credential injection** enabled, the client instead
presents an **opaque session token as its password**; the agent terminates that login locally,
exchanges the token with your control plane for a freshly-minted, short-lived upstream credential,
and **originates its own upstream authentication** with it (Postgres: trust / cleartext / md5 /
SCRAM-SHA-256; MySQL: mysql_native_password / caching_sha2_password). The client therefore never holds
a credential the database would accept directly, and result rows are still masked inline.

```sh
SKYBRIDGE_DB_TYPE=postgres \
SKYBRIDGE_UPSTREAM=db.internal:5432 \
SKYBRIDGE_INJECT_CREDENTIALS=true \
SKYBRIDGE_TOKEN=<agent-service-bearer> \
SKYBRIDGE_CREDENTIAL_EXCHANGE_URL=https://app.example.com/your-control-plane/proxy-exchange \
go run ./cmd/skybridge-agent
```

Your control plane mints the session token however it likes (e.g. a `proxy-session` endpoint that
returns a short-lived token for a given role/connection); the user then, in pgAdmin/psql/DBeaver,
points the client at the **Skybridge listener** (not the database), uses any username, and pastes
the session token **as the password**. Injection covers **Postgres** and **MySQL**; Mongo falls back
to verbatim auth passthrough (logged at startup). See `CredentialExchangeURL`'s request/response
shape in `CONTRACT.md` §3 to implement the control-plane side.

**MySQL specifics.** MySQL's default auth is challenge-response, so the token cannot be recovered from
it. The agent therefore terminates client TLS and switches the client to the **`mysql_clear_password`**
plugin to receive the token in cleartext over the encrypted link — so MySQL injection **requires client
TLS** and the client must enable the cleartext plugin (e.g. `mysql --enable-cleartext-plugin ...`, or
the equivalent checkbox in GUI tools). Upstream, the agent answers `mysql_native_password` or
`caching_sha2_password`; the latter's first-connection "full authentication" sends the password over
the wire, so it **requires upstream TLS** (`SKYBRIDGE_UPSTREAM_TLS`) — RSA-key full auth is not
supported.

**Encrypt the client link (so the token isn't sent in cleartext).** The session token rides in the
client's password, so terminate client TLS at the agent: provide a cert/key (or, for dev, a
self-signed one) and connect the client with `sslmode=require`.

```sh
# dev: ephemeral self-signed cert; clients use sslmode=require (no chain verification)
SKYBRIDGE_DB_TYPE=postgres SKYBRIDGE_UPSTREAM=db.internal:5432 \
SKYBRIDGE_INJECT_CREDENTIALS=true SKYBRIDGE_TOKEN=… \
SKYBRIDGE_CREDENTIAL_EXCHANGE_URL=https://app.example.com/your-control-plane/proxy-exchange \
SKYBRIDGE_CLIENT_TLS_SELF_SIGNED=true \
go run ./cmd/skybridge-agent
# then: psql "host=localhost port=15432 user=me sslmode=require"  (password = the session token)
```

For production provide a real cert via `SKYBRIDGE_CLIENT_TLS_CERT_FILE` / `SKYBRIDGE_CLIENT_TLS_KEY_FILE`
so clients can `sslmode=verify-full`. With client TLS off the agent logs a warning that the token is
sent in the client's cleartext password — keep that link on a trusted hop.

### Upstream TLS (encrypt the agent → database hop)

By default the agent speaks plaintext to the upstream over the trusted in-network path. Set
`SKYBRIDGE_UPSTREAM_TLS` to negotiate TLS with the database after dialing (Postgres `SSLRequest`),
mirroring libpq's `sslmode`:

| Mode | Behaviour |
|---|---|
| `disable` (default) | plaintext to the upstream |
| `prefer` | try TLS, fall back to plaintext if the server declines; **no** certificate verification |
| `require` | TLS mandatory; **no** certificate verification (encrypt only) |
| `verify-ca` | TLS mandatory; verify the certificate **chain** against the trust roots (skips hostname) |
| `verify-full` | TLS mandatory; verify chain **and** hostname |

This is also what unblocks **`rds_iam` credential injection** — the RDS IAM auth token is only
accepted over a TLS connection. For RDS/Aurora, point the trust roots at the AWS RDS CA bundle:

```sh
SKYBRIDGE_DB_TYPE=postgres \
SKYBRIDGE_UPSTREAM=mydb.abc123.us-east-1.rds.amazonaws.com:5432 \
SKYBRIDGE_UPSTREAM_TLS=verify-full \
SKYBRIDGE_UPSTREAM_TLS_CA_FILE=/etc/ssl/rds/global-bundle.pem \
go run ./cmd/skybridge-agent
```

`prefer`/`require` encrypt the hop but do **not** authenticate the database; use `verify-ca` (handy
when reaching the DB by IP) or `verify-full` to prove the server's identity.

Upstream TLS is negotiated for **Postgres**, **MySQL** and **Mongo**, but each protocol negotiates it
differently:

- **Postgres** — `SSLRequest` before the protocol starts (transparent).
- **Mongo** — TLS on connect (the server expects the handshake immediately). There is no in-band
  fallback, so `prefer` behaves like `require` for Mongo.
- **MySQL** — TLS is negotiated *inside* the seq-numbered handshake, so the agent inserts its own
  `SSLRequest` packet and shifts the connection-phase sequence ids until auth completes. The upstream
  must advertise `CLIENT_SSL`; with `require`/`verify-*` a server that does not is a hard failure,
  while `prefer` falls back to a plaintext upstream. If the *client* itself speaks TLS to the agent,
  that connection drops to transparent passthrough (no masking, no upstream-TLS interception).

### Dynamic PII overlay (fetched from your control plane)

`SKYBRIDGE_PII_OVERLAY` / `SKYBRIDGE_PII_OVERLAY_FILE` are static. To keep native-client masking in
sync with column rules your own admin surface manages, point the agent at an HTTP endpoint instead:

```sh
SKYBRIDGE_ORG_ID=<org-uuid> \
SKYBRIDGE_TOKEN=<org-scoped-bearer> \
SKYBRIDGE_PII_OVERLAY_URL=https://app.example.com/your-control-plane/pii-overlay \
go run ./cmd/skybridge-agent
```

The agent fetches `{ "columns": { "<column>": "<token>" } }` at startup and re-fetches every
`SKYBRIDGE_PII_OVERLAY_POLL_SECONDS`, hot-swapping the overlay in place (no restart). Your control
plane decides what "columns" contains — e.g. projecting a per-org PII schema into per-category
tokens (`email → [email]`, `ssn → [ssn]`), excluding business identifiers / operational columns. A
failed fetch leaves the last-known (or static `SKYBRIDGE_PII_OVERLAY`) rules intact. See
`internal/agent/overlay_source.go` for the exact request/response contract, including
`SKYBRIDGE_PII_OVERLAY_ORG_HEADER` if you need a header name other than the default
`X-Organization-Id`.

## Layout

```
cmd/skybridge-agent     egress agent: listener OR tunnel mode
cmd/skybridge-gateway   relay gateway: agent endpoint + client listeners
cmd/skybridge-edge      unified edge: call-home transport + AWS reads + optional wire proxy
internal/wire           wire engines: postgres, mysql, mongo
internal/mask           masking pipeline: remote (Presidio) masker + path overlay + column overlay
internal/pathlabel      docpath (nested-document path walking) + label (path-scoped Store/Label types)
internal/tunnel         egress multiplexed transport
internal/gateway        agent registry + relay + optional session recording
internal/edge           edge tool dispatch: envelope, read-only AWS policy, executor
internal/edge/transport egress-only gRPC call-home client (Connect/serve/reconnect)
internal/certstore      persists issued mTLS identity (local disk, optionally mirrored to AWS
                         Secrets Manager) so redeployed tasks skip re-enrollment
internal/genpb          generated gRPC stubs (run `make gen` to refresh)
internal/config         SKYBRIDGE_* environment config
```

### The `skybridge-edge` binary

`skybridge-edge` is the single thing a customer installs. It dials **out** (egress-only) to the SaaS
Connector Gateway and serves dispatched **single read-only tool calls** locally — chiefly live AWS
reads against the customer account (`aws_readonly_cli`, `cloudwatch_logs_insights`,
`cloudwatch_metrics`) — and, when DB targets are configured, also runs the co-located wire proxy. The
LLM agent loop and platform-coupled tools stay on the SaaS side.

```sh
SKYBRIDGE_EDGE_GATEWAY=gateway.example.com:8020 \
SKYBRIDGE_ORG_ID=org-123 SKYBRIDGE_EDGE_ID=edge-1 SKYBRIDGE_TOKEN=... \
SKYBRIDGE_AWS_REGION=us-east-1 \
go run ./cmd/skybridge-edge
```

Or set a single `SKYBRIDGE_KEY` instead of `SKYBRIDGE_EDGE_GATEWAY`/`SKYBRIDGE_ORG_ID`/`SKYBRIDGE_TOKEN`
(the connector enrollment mint returns this as `customer_handoff.connector_key`):

```sh
SKYBRIDGE_KEY="skybridge://org-123:<enrollment-token>@gateway.example.com?edge_id=edge-1" \
SKYBRIDGE_AWS_REGION=us-east-1 \
go run ./cmd/skybridge-edge
```

`SKYBRIDGE_KEY` only seeds defaults — any discrete `SKYBRIDGE_*` var above still overrides it, so
existing deployments and scripts keep working unchanged. The connector-gateway (`:7100`) and enroll
(`:7101`) ports are fixed by convention and derived from the key's bare host.

#### Auth: bearer token vs. mTLS

| Mode | Set | Behavior |
|---|---|---|
| Bearer (default) | `SKYBRIDGE_TOKEN` | Simple shared secret over TLS. Fine for a quick start. |
| mTLS (hardened) | `SKYBRIDGE_CA_BUNDLE_PEM`/`_FILE` + `SKYBRIDGE_ENROLLMENT_TOKEN` | The edge generates a keypair, calls `Enroll` once with the one-time token to get a signed client cert, then connects with mTLS. Preferred for production. |

The issued cert is cached under `SKYBRIDGE_TLS_DIR` and reused on restart — no new token needed
until it's actually close to expiry.

#### Keeping mTLS identity alive across redeploys

⚠️ **On ECS/Fargate, a plain `SKYBRIDGE_TLS_DIR` cache does not survive a redeploy.** Any task
replacement (new image, new task definition, a CPU/memory bump — anything that spins up a fresh
task) wipes that disk. Since `SKYBRIDGE_ENROLLMENT_TOKEN` is **single-use**, the new task can't just
re-enroll: the token was already consumed by the task it replaced, and the deploy fails.

**Fix:** point the edge at an AWS Secrets Manager secret and it will keep its identity there too,
so a replacement task picks up right where the old one left off — no new token required.

| Identity | Env var |
|---|---|
| Connector (edge → Connector Gateway) | `SKYBRIDGE_IDENTITY_SECRET_ARN` |
| Query Studio (edge → Studio Gateway) | `SKYBRIDGE_STUDIO_IDENTITY_SECRET_ARN` |
| Wire-mTLS (agent → relay gateway tunnel) | `SKYBRIDGE_WIRE_MTLS_IDENTITY_SECRET_ARN` |

Point one of these at a secret ARN the task's IAM role can `GetSecretValue`/`PutSecretValue` on
(`internal/certstore`), and the edge mirrors its cert there on first enrollment, then loads from it
on every subsequent start.

## Docs

- [`CONTRACT.md`](./CONTRACT.md) — the tunnel wire format and the gateway → control-plane HTTP
  session contract.
- All `SKYBRIDGE_*` settings are documented inline in `internal/config/config.go`.

## License

Apache-2.0 — see [`LICENSE`](./LICENSE).
