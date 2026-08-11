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
[Performance and tuning](#performance-and-tuning) ·
[The `skybridge-edge` binary](#the-skybridge-edge-binary) · [Layout](#layout) ·
[Database support](#database-support-at-a-glance) ·
[REDACTION.md](./REDACTION.md) (deep dive, with a live demo GIF)

### Database support at a glance

| Database  | Wire protocol     | Transparent wire proxy (`internal/wire`) | One-shot exec (`dbquery`/`dbexec`, `querystudio` tag) |
|-----------|-------------------|:-----------------------------------------:|:-------------------------------------------------------:|
| Postgres  | native TCP        | ✅ | ✅ |
| MySQL     | native TCP        | ✅ | ✅ |
| MongoDB   | native TCP (BSON) | ✅ | ✅ |
| Snowflake | HTTPS/REST        | ❌ — no wire protocol to proxy | ✅ (querystudio only) |

Postgres/MySQL/Mongo get a full native-client wire proxy: point `psql`/`mysql`/`mongosh` (or an app
driver) straight at the agent and it masks rows in flight. Snowflake speaks HTTPS/REST, not a native
TCP protocol, so there's no handshake to transparently proxy — it's supported only via the optional
`querystudio` build tag's one-shot query-exec path, sharing the same masking pipeline.

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

### Install via Homebrew

```sh
brew tap curlix-io/skybridge https://github.com/curlix-io/skybridge
brew install skybridge
```

Installs `skybridge-agent`, `skybridge-gateway`, and `skybridge-edge` (macOS/Linux, amd64/arm64).
The formula (`Formula/skybridge.rb`) is regenerated and pushed to this repo's `main` branch on
every tagged release by `.goreleaser.yaml`'s `brews:` block, installing from that release's tar.gz
archives — see the repo's [Releases](https://github.com/curlix-io/skybridge/releases) page (prebuilt
container images are published separately to
[github.com/curlix-io/skybridge/packages](https://github.com/curlix-io/skybridge/packages), see
[`scripts/push-ghcr.sh`](./scripts/push-ghcr.sh)). `skybridge-edge` is the single binary most
customers run to connect to Curlix — see [The `skybridge-edge` binary](#the-skybridge-edge-binary).

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
brings up Microsoft Presidio's analyzer + anonymizer alongside the agent, using the same
Gunicorn worker/preload configuration Presidio's own deployment docs recommend:

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

The compose file runs `skybridge-edge` (not the plain agent) so this same stack, unchanged, also
covers AWS/k8s tool dispatch — just set `SKYBRIDGE_EDGE_GATEWAY` (plus `SKYBRIDGE_ORG_ID`/
`SKYBRIDGE_EDGE_ID`) alongside `SKYBRIDGE_UPSTREAM` and edge dials out to a Connector Gateway in
the same process that's already running the wire proxy; leave `SKYBRIDGE_EDGE_GATEWAY` unset to run
the wire proxy alone, no outbound gateway dial. That keeps a full-featured install at 3 containers:
`edge` + the two Presidio containers.

`deploy/docker-compose.yml` also has an opt-in `--profile labeller` for `skybridge-labeller`, off
by default since it needs external services this repo doesn't ship (an LLM endpoint + control-plane
`pii-path-labels` URL). Bring it in with `docker compose --profile labeller up -d`.

### Test data for Postgres, MySQL, and MongoDB

[`examples/demo/`](./examples/demo/) ships the same small, fabricated customer dataset — name,
email, SSN, a free-text note, a JSON blob — seeded identically into Postgres
([`seed.sql`](./examples/demo/seed.sql)), MySQL
([`seed.mysql.sql`](./examples/demo/seed.mysql.sql)), and MongoDB
([`seed.mongo.js`](./examples/demo/seed.mongo.js)), so the same before/after redaction can be shown
across all three database types (`./examples/demo/run-demo.sh up` loads all three and starts an
agent trio; see [Redaction in action](#redaction-in-action-sql-rows-json-bson-and-free-text) above
for the exact rows). It's intentionally tiny (a handful of rows) — enough to demo, not to load-test.

For a larger, still-synthetic PII test corpus to seed yourself, consider
[`ai4privacy/pii-masking-200k`](https://huggingface.co/datasets/ai4privacy/pii-masking-200k) on
Hugging Face — machine-generated (no real personal data), labeled by PII type, and independent of
Skybridge. Verify its current license/schema on the dataset page before using it; there's no
built-in loader for it in this repo, so you'd write a small script to convert its rows into
`INSERT`/`insertMany` statements for whichever database you're testing against.

### Docker-based end-to-end demos

Two standalone Docker Compose setups exercise real code paths against real containers — each is
self-contained (its own `docker-compose.yml`, no shared state with the demos above):

**AI path-labelling, with vs. without** ([`examples/aiclassifier-demo/`](./examples/aiclassifier-demo/)) —
runs the real `internal/pathlabel/aiclassifier` `Scanner`/`LLM` code against a stub LLM server,
printing a side-by-side of what gets proposed today (content-only detection, gated on live query
traffic) vs. with the AI classifier (column name + samples, independent of traffic). See
[Roadmap: AI-based path labelling](#roadmap-ai-based-path-labelling-proposed) above for the design
this demos.

```sh
cd examples/aiclassifier-demo
docker compose up --build --abort-on-container-exit
docker compose down
```

**Typed-column (BSON) redaction against a real MongoDB** ([`examples/mongo-typekind-demo/`](./examples/mongo-typekind-demo/)) —
runs a real `skybridge-agent` (mongo mode) in front of a real MongoDB, wired to a stub control-plane
server serving one confirmed `manual` label on a BSON datetime field, and a runner that queries
through the agent and asserts the typed field comes back redacted to a type-valid placeholder
rather than left raw or corrupted (`mask.Column.TypeKind`, see [How masking
works](#how-masking-works) below). The confirmed label takes effect on the agent's next path-label
poll tick (~15s), not instantly, so the runner retries until it observes the redaction — don't pass
`--abort-on-container-exit` here, since the one-shot seed container exits successfully as soon as
it's done and would otherwise stop the whole stack prematurely.

```sh
cd examples/mongo-typekind-demo
docker compose up --build      # watch the `runner` container's logs for PASS/FAIL
docker compose down
```

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

### Path-scoped labels (`internal/pathlabel`, `mask.PathOverlay`)

`mask.PathOverlay` (`internal/mask/pathoverlay.go`) is wired into the live chain in
`buildMaskerWithOverlay` (`internal/agent/agent.go`) whenever `SKYBRIDGE_PATH_LABEL_URL` is set,
backed by `internal/pathlabel/remotestore.Store` — a control-plane-fetched `label.Store` (pull
confirmed labels, push detector-proposed ones), not the in-memory reference implementation. It
looks up a label keyed on `(ObjectID, FieldPath)` — something a bare column-name rule can never
express, e.g. distinguishing `order.total` from `user.total`.

Its effectiveness depends on the wire engine resolving real per-row table/collection identity:
`internal/edge/dbquery`'s one-shot exec path (`internal/edge/dbquery/mask.go`) resolves it for
every query regardless of database — `"{org}:{driver}:{database}:{table}"`, with Mongo documents
walked *nested* rather than flattened first (`internal/pathlabel/docpath`), so a
`profile.contact.email` leaf is addressable independently of a top-level `email` column. All three
wire-proxy engines resolve it too: MySQL parses real per-column table identity off the wire (schema
+ `org_table` from the column-definition packet); Mongo (`internal/wire/mongo`) correlates each
`find`/`aggregate`/`getMore` request's collection with its reply via the wire protocol's
`requestID`/`responseTo` fields, including nested document paths; and Postgres
(`internal/wire/postgres`) — which only has a numeric table OID on the wire, never a name — resolves
it via a dedicated `pg_class`/`pg_namespace` lookup connection the agent opens for itself, configured
with `SKYBRIDGE_POSTGRES_CATALOG_DSN` (see [Postgres table-identity resolution](./REDACTION.md#postgres-table-identity-resolution)
for why this one needs its own credential rather than reusing the client's). Unconfigured, Postgres
connections pass an empty `ObjectID`, which `PathOverlay` treats as "no label available" and falls
through safely, same as if it weren't configured at all.

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
independent rules despite sharing a field name; see `PathOverlay` above — live for the `dbquery`
one-shot exec path and all three wire proxies today, Postgres's requiring
`SKYBRIDGE_POSTGRES_CATALOG_DSN`):**

```
{ "profile": { "email": "jane@doe.com", "name": "Jane" }, "order": { "total": 42 } }
   →
{ "profile": { "email": "[redacted]", "name": "Jane" }, "order": { "total": 42 } }
```

Only `profile.email` is redacted — `order.total` and `profile.name` carry no label, so they fall
through every layer untouched, exactly as the fallthrough-on-miss contract guarantees.

### Roadmap: AI-based path labelling (proposed)

Today, a `PathOverlay` label only exists if a human sets it, or if Presidio's content detector
happens to fire on a sampled leaf value during live query traffic (`internal/edge/dbquery/mask.go`'s
`proposeLeaf`). A proposed AI classifier (see
[`docs/AI_PATH_LABELLING_DESIGN.md`](./docs/AI_PATH_LABELLING_DESIGN.md)) would run as a separate,
periodic scan — independent of query traffic — that proposes labels using both column *name* and
sampled *values*, so coverage no longer depends on someone having queried a table first:

```
 ┌───────────────────────────────────────────────────────────────────────┐
 │                    Periodic classification scan (offline)             │
 │                                                                        │
 │   read-only catalog          ┌──────────────┐                        │
 │   credential (per DB) ─────► │  sample rows │                        │
 │                               │ per ObjectID │                        │
 │                               └──────┬───────┘                        │
 │                                      │ column name + N sampled values │
 │                                      ▼                                │
 │                          ┌───────────────────────┐                   │
 │                          │  Classifier interface  │                   │
 │                          │ ┌───────────────────┐ │                   │
 │                          │ │ A) LLM API-backed  │ │  pluggable,       │
 │                          │ │    (name+samples   │ │  same output      │
 │                          │ │    → category)     │ │  either way        │
 │                          │ ├───────────────────┤ │                   │
 │                          │ │ B) self-hosted NER │ │                   │
 │                          │ │ (fine-tuned NER)   │ │                   │
 │                          │ └───────────────────┘ │                   │
 │                          └───────────┬───────────┘                   │
 │                                      │ {category, profile, confidence}│
 └──────────────────────────────────────┼────────────────────────────────┘
                                        ▼
                     label.Store.Put(..., Source: SourceProposed)
                                        │
                                        ▼
                     ┌──────────────────────────────────────┐
                     │   remotestore.Store (control plane)   │
                     │   pii-path-labels/propose             │
                     └───────────────────┬────────────────────┘
                                         │ steward reviews & confirms
                                         ▼
                     Source flips: proposed ──► manual/platform
                                         │
                                         ▼            (only confirmed labels redact live)
 ┌───────────────────────────────────────────────────────────────────────┐
 │                     Live wire-proxy masking chain                     │
 │        Remote → PathOverlay (confirmed labels only) → Overlay         │
 └───────────────────────────────────────────────────────────────────────┘
```

Key properties carried over from the existing design, unchanged by this addition:

- The classifier only ever writes `Source: SourceProposed` — nothing it proposes redacts live until
  a steward confirms it, exactly like today's Presidio-driven `proposeLeaf` proposals.
- It runs **offline**, never on the query hot path — an LLM/NER call is too slow/costly to sit in
  front of a live database session.
- Backend (LLM API vs. a self-hosted fine-tuned NER model) is a deployment choice behind one
  interface, not a fork in the masking chain.

See the design doc for the full rationale, vendor/OSS landscape survey, and how this also lays the
groundwork for a streaming/CDC masking extension (a schema-registry-keyed `ObjectID` instead of a
live wire-protocol one).

## Configure

Set these as environment variables (full list in `internal/config/config.go`):

| Variable | Default | What it does |
|---|---|---|
| `SKYBRIDGE_UPSTREAM` | — | upstream database `host:port` (**required**) |
| `SKYBRIDGE_DB_TYPE` | `postgres` | `postgres`, `mysql`, or `mongodb` |
| `SKYBRIDGE_LISTEN` | `:15432` / `:13306` / `:27018` | local address clients connect to |
| `SKYBRIDGE_PII_OVERLAY` | — | JSON `{ "column": "[redacted]" }` map you define (static) |
| `SKYBRIDGE_PII_OVERLAY_FILE` | — | path to a YAML or JSON file with the same column->token map (see [`examples/pii-overlay.yaml`](./examples/pii-overlay.yaml)) — easier to author/diff/commit than inline JSON; takes priority over `SKYBRIDGE_PII_OVERLAY` when both are set, falling back to it if the file is missing/invalid. Also the only form that accepts a `partial_mask: true` rule per column (keep the last 4 characters, mask the rest) instead of a plain replacement token — `SKYBRIDGE_PII_OVERLAY` stays token-only |
| `SKYBRIDGE_PII_OVERLAY_URL` | — | control-plane endpoint to fetch the org's projected overlay (`GET /your-control-plane/pii-overlay`); enables dynamic, hot-swapped masking |
| `SKYBRIDGE_PII_OVERLAY_TOKEN` | `SKYBRIDGE_TOKEN` | bearer token for the overlay fetch |
| `SKYBRIDGE_PII_OVERLAY_POLL_SECONDS` | `60` | overlay refresh interval (min 15s; `-1` = fetch once at startup) |
| `SKYBRIDGE_MASK_ANALYZE_URL` | — (`http://presidio-analyzer:3000/analyze` under `deploy/docker-compose.yml`) | enable content masking: any `POST /analyze` service — Microsoft Presidio by default |
| `SKYBRIDGE_MASK_ANONYMIZE_URL` | — (`http://presidio-anonymizer:3000/anonymize` under compose) | …paired `POST /anonymize` service |
| `SKYBRIDGE_MASK_LANGUAGE` | `en` | language passed to the analyzer |
| `SKYBRIDGE_MASK_ENTITIES` | — (low-cost regex set: `EMAIL_ADDRESS,PHONE_NUMBER,CREDIT_CARD,US_SSN,IP_ADDRESS,IBAN_CODE,CRYPTO`) | comma-separated Presidio entity types to detect; NER-backed types (`PERSON`, `LOCATION`, `ORGANIZATION`, `NRP`) are opt-in — they run full spaCy inference per value and are prone to false positives on ordinary business data |
| `SKYBRIDGE_MASK_ANONYMIZERS` | — (blanket `{"DEFAULT":{"type":"replace","new_value":"[redacted]"}}`) | JSON Presidio "anonymizers" object, one strategy per entity type — e.g. partial-mask an SSN instead of a flat replace |
| `SKYBRIDGE_MASK_ALLOW_LIST` | — | comma-separated literal values or regex patterns (per `SKYBRIDGE_MASK_ALLOW_LIST_MATCH`) to never report as PII — suppress a known-safe recurring false positive without disabling an entity type or writing a custom recognizer |
| `SKYBRIDGE_MASK_ALLOW_LIST_MATCH` | `exact` | `exact` or `regex` — how `SKYBRIDGE_MASK_ALLOW_LIST` entries are interpreted; meaningless when the allow list is empty |
| `SKYBRIDGE_MASK_MODE` | `best-effort` | `best-effort` forwards a value unmasked if the remote masker errors/is unreachable (a masker outage never blocks a query); `strict` aborts the row/connection instead so unmasked content never reaches the client |
| `SKYBRIDGE_INJECT_CREDENTIALS` | `false` | enable credential handoff (clients present an opaque session token, not a DB password) |
| `SKYBRIDGE_CREDENTIAL_EXCHANGE_URL` | — | control-plane endpoint that swaps a session token for an upstream credential (`POST /your-control-plane/proxy-exchange`) |
| `SKYBRIDGE_CREDENTIAL_EXCHANGE_TOKEN` | `SKYBRIDGE_TOKEN` | bearer for the exchange call |
| `SKYBRIDGE_CLIENT_TLS_CERT_FILE` / `_PEM` | — | server cert (Postgres) — enables terminating client TLS so the token isn't sent in cleartext |
| `SKYBRIDGE_CLIENT_TLS_KEY_FILE` / `_PEM` | — | matching private key |
| `SKYBRIDGE_CLIENT_TLS_SELF_SIGNED` | `false` | dev: generate an ephemeral self-signed cert at startup (clients use `sslmode=require`) |
| `SKYBRIDGE_UPSTREAM_TLS` | `disable` | agent→database TLS (Postgres / MySQL / Mongo): `disable` \| `prefer` \| `require` \| `verify-ca` \| `verify-full` |
| `SKYBRIDGE_UPSTREAM_TLS_CA_FILE` / `_PEM` | system roots | trust roots used by `verify-ca` / `verify-full` (e.g. the RDS CA bundle) |
| `SKYBRIDGE_UPSTREAM_TLS_SERVER_NAME` | dial host | override the verified hostname / SNI sent to the upstream |
| `SKYBRIDGE_POSTGRES_CATALOG_DSN` | — | dedicated, read-only Postgres credential (`postgres://user:pass@host:port`) the agent uses on a separate connection it owns for `pg_class`/`pg_namespace` lookups, resolving `PathOverlay`'s table identity for Postgres wire-proxy connections (see [Path-scoped labels](./REDACTION.md#path-scoped-labels-mask-pathoverlay)); unset leaves Postgres's `ObjectID` unresolved, same as before this existed |

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
returns a short-lived token for a given role/connection); the user then, in pgAdmin/psql/DBeaver/
mongosh, points the client at the **Skybridge listener** (not the database), uses any username, and
pastes the session token **as the password**. Injection covers **Postgres**, **MySQL**, and
**Mongo**. See `CredentialExchangeURL`'s request/response shape in `CONTRACT.md` §3 to implement
the control-plane side.

**MySQL specifics.** MySQL's default auth is challenge-response, so the token cannot be recovered from
it. The agent therefore terminates client TLS and switches the client to the **`mysql_clear_password`**
plugin to receive the token in cleartext over the encrypted link — so MySQL injection **requires client
TLS** and the client must enable the cleartext plugin (e.g. `mysql --enable-cleartext-plugin ...`, or
the equivalent checkbox in GUI tools). Upstream, the agent answers `mysql_native_password` or
`caching_sha2_password`; the latter's first-connection "full authentication" sends the password over
the wire, so it **requires upstream TLS** (`SKYBRIDGE_UPSTREAM_TLS`) — RSA-key full auth is not
supported.

**Mongo specifics.** Unlike Postgres/MySQL, a MongoDB driver will not auto-discover an
agent-forced mechanism — real MongoDB servers never advertise `PLAIN` via `hello`'s
`saslSupportedMechs`, so **the client must be explicitly configured with `authMechanism=PLAIN`**
(e.g. `mongodb://user:<token>@host:port/?authMechanism=PLAIN`) to present the session token; there
is no server-side trick to force this the way MySQL's `AuthSwitchRequest` does. The agent
terminates client TLS (Mongo has no in-band STARTTLS, so the TLS handshake happens immediately on
connect, before `hello`) and answers the client's `saslStart(PLAIN)` directly — no `saslContinue`
round trip, unlike SCRAM. Upstream, the agent originates a fresh SCRAM-SHA-256 conversation,
falling back to SCRAM-SHA-1 only if the upstream reports `MechanismUnavailable` for this user
(MongoDB <4.0, or a user provisioned with SHA-1-only credentials).

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

## Performance and tuning

### Benchmarks

The masking chain (`internal/mask`) is the only per-row work the agent does beyond copying bytes —
wire parsing itself is a single pass over the protocol frame. `internal/mask/bench_test.go` benchmarks
the local, no-network masking layers in isolation (the `Remote`/Presidio layer is excluded — it's an
HTTP round trip, dominated by network latency, not CPU). Reproduce with:

```sh
go test ./internal/mask/... -run NONE -bench . -benchtime 2s
```

Measured on an Apple M3 (`GOMAXPROCS=8`), one 5-column row (2 free-text, 2 typed, 1 id) per op:

| Benchmark | ns/op | allocs/op | What it measures |
|---|---:|---:|---|
| `Overlay_MaskRow` | ~67 | 2 | Static column→token overlay (`SKYBRIDGE_PII_OVERLAY`), one matching column |
| `PathOverlay_MaskRow_Hit` | ~140 | 2 | Path-scoped label lookup (`SKYBRIDGE_PATH_LABEL_URL`), label present |
| `PathOverlay_MaskRow_Miss` | ~35 | 1 | Path-scoped lookup, no label — falls through to the next layer |
| `Chain_OverlayOnly` | ~69 | 2 | Default OSS deployment shape: overlay only, no remote masker configured |
| `Chain_PathOverlayAndOverlay` | ~182 | 3 | PathOverlay + Overlay layered, one hit each |

These are microbenchmarks of the masking layers alone, not end-to-end query latency — real
per-query latency is dominated by the upstream database round trip and, if configured, the
`Remote`/Presidio HTTP call (typically single-digit milliseconds, network-dependent). The takeaway:
local masking overhead per row is sub-microsecond and not the bottleneck in any realistic deployment;
size the remote masker (Presidio) and the database itself for throughput, not this layer.

### Tuning environment variables

All of the following are optional; every one has a working default. See
`internal/config/config.go` for the authoritative list (this repo's docstrings are the source of
truth — the table below is a summary, not a replacement).

| Variable | Default | Effect |
|---|---|---|
| `SKYBRIDGE_MASK_MODE` | `best-effort` | `strict` aborts the row/connection on a masker failure instead of forwarding it unmasked — trades availability for a stronger no-unmasked-leak guarantee. |
| `SKYBRIDGE_MASK_ENTITIES` | unset (low-cost regex set) | Restricting `/analyze` to specific entity types avoids Presidio's full NER pass (spaCy inference) on every value; only add `PERSON`/`LOCATION`/`ORGANIZATION`/`NRP` if you need them — they're the expensive, false-positive-prone tiers. |
| `SKYBRIDGE_PII_OVERLAY_POLL_SECONDS` | `60` | How often the dynamic column overlay re-fetches from your control plane. Lower = fresher rules, more request volume against that endpoint. |
| `SKYBRIDGE_PII_RECOGNIZERS_POLL_SECONDS` | `60` | Same trade-off for the dynamic custom-recognizers source (`SKYBRIDGE_PII_RECOGNIZERS_URL`). |
| `SKYBRIDGE_PATH_LABEL_POLL_SECONDS` | `60` (floored) | How often confirmed path-scoped labels are pulled (`internal/pathlabel/remotestore`). |
| `SKYBRIDGE_PATH_LABEL_PUSH_SECONDS` | `15` (floored) | How often detector-proposed labels are pushed upstream. More frequent pushes surface new proposals faster at the cost of more outbound requests. |
| `SKYBRIDGE_MASKING_METRICS_PUSH_SECONDS` | `60` (floored) | Push interval for masking-outcome metrics (counts only, never values). Purely observability — has no effect on masking behavior or query latency. |
| `SKYBRIDGE_SESSION_REPLAY_MAX_BYTES` | `5 MiB` | Caps the in-memory transcript buffer per session when `SKYBRIDGE_SESSION_REPLAY_ENABLED=true`. Lower this on memory-constrained deployments with many concurrent sessions. |
| `SKYBRIDGE_STUDIO_MAX_SESSIONS` | `8` | (`querystudio` tag) Caps concurrent Query Studio dispatch sessions on one edge process. |
| `SKYBRIDGE_GW_CLIENT_CONN_PER_MIN` / `SKYBRIDGE_GW_ORG_CONN_PER_MIN` | unset (no limit) | Gateway-side per-client / per-org connection-rate ceilings — the main throughput/abuse knobs on `skybridge-gateway` in tunnel mode. |

Everything else in `internal/config/config.go` (TLS, credential exchange, enrollment) is
correctness/security configuration, not a performance knob.

## Layout

```
cmd/skybridge-agent     egress agent: listener OR tunnel mode
cmd/skybridge-gateway   relay gateway: agent endpoint + client listeners
cmd/skybridge-edge      unified edge: call-home transport + AWS reads + optional wire proxy
internal/wire           wire engines: postgres, mysql, mongo
internal/wire/scram     protocol-agnostic SCRAM-SHA-1/SHA-256 client-conversation math, shared by
                        postgres and mongo's credential-injection upstream-auth origination
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

See [Database support at a glance](#database-support-at-a-glance) above for which databases get a
wire engine (`internal/wire`) vs. exec-only support (`dbquery`/`dbexec`, `querystudio` tag).

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
- [`deploy/TUNNEL_TESTING.md`](./deploy/TUNNEL_TESTING.md) — standing up the TUNNEL deployment
  shape locally and exposing it via ngrok for an external tester.
- All `SKYBRIDGE_*` settings are documented inline in `internal/config/config.go`.

## License

Apache-2.0 — see [`LICENSE`](./LICENSE).
