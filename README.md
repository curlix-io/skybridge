# Skybridge

[![CI](https://github.com/curlix-io/skybridge/actions/workflows/ci.yml/badge.svg)](https://github.com/curlix-io/skybridge/actions/workflows/ci.yml)
[![Go Report Card](https://goreportcard.com/badge/github.com/curlix-io/skybridge)](https://goreportcard.com/report/github.com/curlix-io/skybridge)
[![Latest release](https://img.shields.io/github/v/release/curlix-io/skybridge)](https://github.com/curlix-io/skybridge/releases)
[![License](https://img.shields.io/github/license/curlix-io/skybridge)](./LICENSE)

**Jump to:** [1. What is Skybridge?](#1-what-is-skybridge) ·
[2. How it works & how to run it](#2-how-it-works--how-to-run-it) ·
[Quick start](#quick-start) · [How masking works](#how-masking-works) · [Configure](#configure) ·
[Performance and tuning](#performance-and-tuning) · [The `edge` role](#the-edge-role) ·
[Layout](#layout) · [REDACTION.md](./REDACTION.md) (deep dive, with a live demo GIF)

---

## 1. What is Skybridge?

**TL;DR:** Skybridge sits between your apps/tools and your database. People and tools still connect
to it exactly like they would to the real database — but before any row of data leaves your network,
Skybridge blacks out things like emails, phone numbers, and SSNs. Nothing that isn't already inside
your network ever gets a direct line to your raw data.

Think of it as a one-way mirror in front of your database: everyone on the outside still sees rows
of data come back when they run a query — they just don't see the sensitive parts.

```mermaid
%%{init: {"theme": "base", "themeVariables": {"primaryColor": "#0f766e", "primaryTextColor": "#f8fafc", "primaryBorderColor": "#134e4a", "lineColor": "#64748b", "fontSize": "15px"}}}%%
flowchart LR
    person["👤 Person or app<br/>running a normal query"]
    sb["🛡️ Skybridge<br/>(lives inside your network)"]
    db[("🗄️ Your database")]

    person -->|"query"| sb
    sb -->|"query"| db
    db -->|"raw rows"| sb
    sb -->|"same rows,<br/>sensitive fields blacked out"| person

    classDef client fill:#e2e8f0,stroke:#475569,color:#0f172a
    classDef bridge fill:#0f766e,stroke:#134e4a,color:#f8fafc
    classDef store fill:#1e293b,stroke:#0f172a,color:#f8fafc
    class person client
    class sb bridge
    class db store
```

**Why teams run this in front of a database:**

- **Nobody has to trust every tool/person to handle raw PII carefully.** The masking happens once,
  in one place, automatically — not by convention, not by hoping every script/dashboard/analyst
  redacts things correctly on their own.
- **It doesn't dial in from the outside.** Skybridge only ever calls *out* from inside your network
  — nothing external is ever given a door into your database. That egress-only property is true no
  matter which of the three setups (below) you use.
- **It doesn't touch the database itself.** No proxy driver to install, no schema changes, no
  extension to load — it's a small program that sits in front of the database and speaks the same
  protocol a normal client would.
- **If something goes wrong, it fails safe.** If Skybridge can't understand a piece of data, it
  passes it through untouched rather than guessing, corrupting it, or crashing the connection.

**Who this is for:** security/compliance-minded teams who need a real answer to "who can see raw
customer PII", and engineers who want that answer to require zero changes to how people already
query the database (same tools, same drivers, same queries — `psql`, `mysql`, `mongosh`, your app's
existing DB driver).

Read on for the technical detail — how it's deployed, how the masking actually works layer by layer,
and how to run it yourself.

## 2. How it works & how to run it

### Database support at a glance

| Database  | Wire protocol     | Transparent wire proxy (`internal/wire`) | One-shot exec (`dbquery`/`dbexec`) |
|-----------|-------------------|:-----------------------------------------:|:-------------------------------------------------------:|
| Postgres  | native TCP        | ✅ | ✅ |
| MySQL     | native TCP        | ✅ | ✅ |
| MongoDB   | native TCP (BSON) | ✅ | ✅ |
| Snowflake | HTTPS/REST        | ❌ — no wire protocol to proxy | ✅ |

Postgres/MySQL/Mongo get a full native-client wire proxy: point `psql`/`mysql`/`mongosh` (or an app
driver) straight at the agent and it masks rows in flight. Snowflake speaks HTTPS/REST, not a native
TCP protocol, so there's no handshake to transparently proxy — it's supported only via the
one-shot query-exec path (`edge` role), sharing the same masking pipeline.

### Deployment shapes

```mermaid
%%{init: {"theme": "base", "themeVariables": {"primaryColor": "#0f766e", "primaryTextColor": "#f8fafc", "primaryBorderColor": "#134e4a", "lineColor": "#64748b", "fontSize": "15px"}}}%%
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

    classDef client fill:#e2e8f0,stroke:#475569,color:#0f172a
    classDef bridge fill:#0f766e,stroke:#134e4a,color:#f8fafc
    classDef store fill:#1e293b,stroke:#0f172a,color:#f8fafc
    classDef saasNode fill:#c2410c,stroke:#7c2d12,color:#f8fafc
    class c1 client
    class agent,edge bridge
    class db,aws store
    class gw,cg saasNode
    style clients fill:#f1f5f9,stroke:#94a3b8,color:#0f172a
    style net fill:#ecfdf5,stroke:#0f766e,color:#0f172a
    style saas fill:#fff7ed,stroke:#c2410c,color:#0f172a
```

Skybridge ships three deployment shapes; all of them keep the customer side **egress-only** (it
dials out, nothing dials in):

- **Listener** — native clients connect straight to the agent. Simplest setup.
- **Tunnel** — the agent dials **out** to a gateway; clients connect to the gateway, which relays
  already-masked bytes over the tunnel. Masking still happens at the agent.
- **Edge** — the `edge` role dials **out** to a Connector Gateway and runs dispatched
  **read-only tool calls** locally — chiefly live AWS reads against your account — and can co-host the
  wire proxy in the same process. One install for everything that must run inside your network. See
  [The `edge` role](#the-edge-role) below.

### Roles at a glance

`cmd/skybridge` is a single binary; the role is picked by the first CLI argument
(`skybridge <role>`):

| Role | Command | What it does | Use it when... |
|---|---|---|---|
| **agent** | `skybridge agent` | Sits directly in front of one database, masking PII in-line. Runs in *listener* mode (clients connect to it directly) or *tunnel* mode (dials out to a gateway). | You want the simplest single-database setup. |
| **gateway** | `skybridge gateway` | Client-facing relay endpoint that one or more agents dial out to (tunnel mode). Optionally records session metadata to a control plane. | You're centralizing several agents' tunnels behind one public endpoint. |
| **edge** | `skybridge edge` | Dials out to a Connector Gateway for read-only AWS/k8s tool dispatch, and can co-host the wire proxy in the same process. | This is the role most customers run — one install covering everything. See [The `edge` role](#the-edge-role). |
| **labeller** | `skybridge labeller` | Periodic job that AI-classifies database columns/paths for PII and proposes labels for a human to confirm. | You want path-scoped label coverage without waiting on live query traffic (needs an LLM endpoint + control-plane URL). |

### Quick start

Put the agent in front of your database and point a native client at it.

#### Install via Homebrew

```sh
brew tap curlix-io/skybridge https://github.com/curlix-io/skybridge
brew install skybridge
```

Installs the single `skybridge` binary (macOS/Linux, amd64/arm64) — the role
(`agent`/`gateway`/`edge`/`labeller`) is picked by the first argument at run time.
The formula (`Formula/skybridge.rb`) is regenerated and pushed to this repo's `main` branch on
every tagged release by `.goreleaser.yaml`'s `brews:` block, installing from that release's tar.gz
archives — see the repo's [Releases](https://github.com/curlix-io/skybridge/releases) page (a prebuilt
container image is published separately to
[github.com/curlix-io/skybridge/packages](https://github.com/curlix-io/skybridge/packages), see
[`scripts/push-ghcr.sh`](./scripts/push-ghcr.sh)). `skybridge edge` is the role most
customers run to connect to Curlix — see [The `edge` role](#the-edge-role).

#### Fastest path: column redaction, no external services

Needs only Go ≥ 1.26 — no Docker, no Presidio, no network calls. This uses the column-name
`Overlay` layer only (see [How masking works](#how-masking-works)); it won't catch PII embedded in
free text, but it's the quickest way to see redaction working end to end.

```sh
SKYBRIDGE_UPSTREAM=db.internal:5432 \
SKYBRIDGE_PII_OVERLAY_FILE=./examples/pii-overlay.yaml \
go run ./cmd/skybridge agent
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

#### Full path: add content-detection masking (catches PII in free text too)

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

The compose file runs the `edge` role (not the plain `agent` role) so this same stack, unchanged, also
covers AWS/k8s tool dispatch — just set `SKYBRIDGE_EDGE_GATEWAY` (plus `SKYBRIDGE_ORG_ID`/
`SKYBRIDGE_EDGE_ID`) alongside `SKYBRIDGE_UPSTREAM` and edge dials out to a Connector Gateway in
the same process that's already running the wire proxy; leave `SKYBRIDGE_EDGE_GATEWAY` unset to run
the wire proxy alone, no outbound gateway dial. That keeps a full-featured install at 3 containers:
`edge` + the two Presidio containers.

`deploy/docker-compose.yml` also has an opt-in `--profile labeller` for the `labeller` role, off
by default since it needs external services this repo doesn't ship (an LLM endpoint + control-plane
`pii-path-labels` URL). Bring it in with `docker compose --profile labeller up -d`.

#### Test data for Postgres, MySQL, and MongoDB

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

#### Docker-based end-to-end demos

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
runs a real `skybridge agent` (mongo mode) in front of a real MongoDB, wired to a stub control-plane
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

### How masking works

> For a deeper dive — including a live demo GIF, the anonymizer-strategy config, and exactly what's
> live vs. groundwork in the path-scoped labels layer — see [REDACTION.md](./REDACTION.md).

**TL;DR:** every row passes through a chain of maskers (`mask.Masker.MaskRow`). A miss at one layer
falls through to the next — an unmasked value is never corrupted, only ever left as-is. Order:

```mermaid
%%{init: {"theme": "base", "themeVariables": {"primaryColor": "#0f766e", "primaryTextColor": "#f8fafc", "primaryBorderColor": "#134e4a", "lineColor": "#64748b", "fontSize": "15px"}}}%%
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

    classDef io fill:#e2e8f0,stroke:#475569,color:#0f172a
    classDef step fill:#0f766e,stroke:#134e4a,color:#f8fafc
    class row,out io
    class r1,r2,o1 step
    style remote fill:#ecfdf5,stroke:#0f766e,color:#0f172a
    style overlay fill:#f0fdfa,stroke:#0f766e,color:#0f172a
```

**Layer 1 — `Remote`.** The only layer that inspects the *value itself*, not the field's name — so
it works the same on a typed column and on free text. A thin client for any
[Presidio](https://github.com/data-privacy-stack/presidio)-compatible `analyze`/`anonymize` pair
(`SKYBRIDGE_MASK_ANALYZE_URL`/`_ANONYMIZE_URL`, see [Configure](#configure)). Best-effort: a
transport error, non-200, or zero detected spans all fall through untouched.

**Layer 2 — `Overlay`.** A case-insensitive `column name → replacement token` map
(`SKYBRIDGE_PII_OVERLAY`, static or dynamically fetched — see
[Dynamic PII overlay](#dynamic-pii-overlay-fetched-from-your-control-plane)). No path awareness:
`total` under `order` and `total` under `user` share one rule.

#### Path-scoped labels (`internal/pathlabel`, `mask.PathOverlay`)

**TL;DR:** an optional third layer, enabled by setting `SKYBRIDGE_PATH_LABEL_URL`. It labels by
`(table/collection, field path)` instead of bare column name, so `order.total` and `user.total` can
carry independent rules. Needs real per-row table identity to work, which each engine resolves
differently:

| Engine | How it identifies the table |
|---|---|
| `dbquery` one-shot exec (all DBs) | `"{org}:{driver}:{database}:{table}"`; Mongo walked nested, so `profile.contact.email` is addressable on its own |
| MySQL wire proxy | Parses schema + table straight off the column-definition packet |
| Mongo wire proxy | Correlates each request's collection with its reply via `requestID`/`responseTo` |
| Postgres wire proxy | Only a numeric table OID is on the wire — needs `SKYBRIDGE_POSTGRES_CATALOG_DSN` for a `pg_class` lookup; unset, falls through safely with no label |

Layer 1 (`Remote`) is what gives unstructured-text coverage; layer 2 (`Overlay`) and this layer are
structured-schema shortcuts that skip the network round trip once a field is labelled. All layers
run on every row by default — there's no separate structured/unstructured mode to pick.

#### Redaction in action: SQL rows, JSON, BSON, and free text

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

#### Roadmap: AI-based path labelling (proposed)

**TL;DR:** today a `PathOverlay` label only exists if a human sets it, or Presidio happens to fire
on a sampled value during live traffic. The proposed AI classifier
([`docs/AI_PATH_LABELLING_DESIGN.md`](./docs/AI_PATH_LABELLING_DESIGN.md)) runs as a separate,
periodic, **offline** scan — independent of query traffic — that proposes labels from column name +
sampled values via a pluggable backend (LLM API or a self-hosted NER model). Same
`SourceProposed`-only contract as today: nothing it proposes redacts live until a steward confirms
it.

### Configure

Set these as environment variables. The full authoritative list (including every default) lives
in doc comments in `internal/config/config.go` — the tables below group the same variables by what
they control, which is easier to scan than one flat list.

**Jump to:** [Core](#core-agent-role) · [PII overlay — static](#pii-overlay--static) ·
[PII overlay — dynamic](#pii-overlay--dynamic-fetched-from-your-control-plane) ·
[Content-detection masking](#content-detection-masking-presidio-compatible) ·
[Custom recognizers](#custom-pii-recognizers) · [Masking metrics](#masking-outcome-metrics) ·
[Path-scoped labels](#path-scoped-labels--ai-classification) ·
[Credential handoff](#credential-handoff-the-client-never-holds-a-database-password) ·
[Client TLS](#client-tls-encrypt-native-client-connections) ·
[Upstream TLS](#upstream-tls-encrypt-the-agent--database-hop) ·
[Wire-agent mTLS](#wire-agent-mtls-agent--gateway-tunnel-mode)

#### Core (`agent` role)

| Variable | Default | What it does |
|---|---|---|
| `SKYBRIDGE_UPSTREAM` | — | upstream database `host:port` (**required** in listener mode) |
| `SKYBRIDGE_DB_TYPE` | `postgres` | `postgres`, `mysql`, or `mongodb` |
| `SKYBRIDGE_LISTEN` | `:15432` / `:13306` / `:27018` | local address native clients connect to (listener mode) |
| `SKYBRIDGE_MODE` | `listener` | `listener` (clients connect straight to this agent) or `tunnel` (agent dials out to a gateway) |
| `SKYBRIDGE_GATEWAY` | — | gateway agent-endpoint `host:port` the agent dials **out** to in tunnel mode |
| `SKYBRIDGE_AGENT_ID` | — | stable agent identity (an org's token/key may be shared by many agent processes) |
| `SKYBRIDGE_ORG_ID` | — | tenant this agent belongs to; a gateway routes client connections to this agent by org id |
| `SKYBRIDGE_TOKEN` | — | shared bearer token used as the default for every other `*_TOKEN` var below unless overridden |
| `SKYBRIDGE_TARGETS` | — | JSON array of `{name,addr,db_type}` static targets, listener mode only — tunnel mode resolves targets live per connection instead |
| `SKYBRIDGE_CONNECTION_ROLE` | — | tags this agent's masking-outcome metrics and connection-scoped recognizer lookups (e.g. `primary`, `readonly-replica`) |
| `SKYBRIDGE_LOG_LEVEL` | `info` | `debug` \| `info` \| `warn` \| `error` — set to `debug` for extra per-connection troubleshooting detail; every log line is tagged with a `component` (e.g. `skybridge-agent`) rather than a hardcoded backend name, so it reads the same whether or not a control-plane integration is configured |

Switch databases by changing `SKYBRIDGE_DB_TYPE`; everything else below is identical regardless of
which database you point the agent at.

#### PII overlay — static

| Variable | Default | What it does |
|---|---|---|
| `SKYBRIDGE_PII_OVERLAY` | — | JSON `{ "column": "[redacted]" }` map you define (static) |
| `SKYBRIDGE_PII_OVERLAY_FILE` | — | path to a YAML or JSON file with the same column→token map (see [`examples/pii-overlay.yaml`](./examples/pii-overlay.yaml)) — easier to author/diff/commit than inline JSON; takes priority over `SKYBRIDGE_PII_OVERLAY` when both are set, falling back to it if the file is missing/invalid. Also the only form that accepts a `partial_mask: true` rule per column (keep the last few characters, mask the rest) instead of a plain replacement token — `SKYBRIDGE_PII_OVERLAY` stays token-only |

#### PII overlay — dynamic (fetched from your control plane)

| Variable | Default | What it does |
|---|---|---|
| `SKYBRIDGE_PII_OVERLAY_URL` | — | control-plane endpoint to fetch the org's projected overlay (`GET /your-control-plane/pii-overlay`); enables dynamic, hot-swapped masking |
| `SKYBRIDGE_PII_OVERLAY_TOKEN` | `SKYBRIDGE_TOKEN` | bearer token for the overlay fetch |
| `SKYBRIDGE_PII_OVERLAY_POLL_SECONDS` | `60` | overlay refresh interval (min 15s; `-1` = fetch once at startup) |
| `SKYBRIDGE_PII_OVERLAY_ORG_HEADER` | `X-Organization-Id` | override the request header carrying the org id on the fetch |

See [Dynamic PII overlay](#dynamic-pii-overlay-fetched-from-your-control-plane) below for the full
request/response contract.

#### Content-detection masking (Presidio-compatible)

| Variable | Default | What it does |
|---|---|---|
| `SKYBRIDGE_MASK_ANALYZE_URL` | — (`http://presidio-analyzer:3000/analyze` under `deploy/docker-compose.yml`) | enable content masking: any `POST /analyze` service — Microsoft Presidio by default |
| `SKYBRIDGE_MASK_ANONYMIZE_URL` | — (`http://presidio-anonymizer:3000/anonymize` under compose) | …paired `POST /anonymize` service |
| `SKYBRIDGE_MASK_LANGUAGE` | `en` | language passed to the analyzer |
| `SKYBRIDGE_MASK_ENTITIES` | — (low-cost regex set: `EMAIL_ADDRESS,PHONE_NUMBER,CREDIT_CARD,US_SSN,IP_ADDRESS,IBAN_CODE,CRYPTO`) | comma-separated Presidio entity types to detect; NER-backed types (`PERSON`, `LOCATION`, `ORGANIZATION`, `NRP`) are opt-in — they run full spaCy inference per value and are prone to false positives on ordinary business data |
| `SKYBRIDGE_MASK_ANONYMIZERS` | — (blanket `{"DEFAULT":{"type":"replace","new_value":"[redacted]"}}`) | JSON Presidio "anonymizers" object, one strategy per entity type — e.g. partial-mask an SSN instead of a flat replace |
| `SKYBRIDGE_MASK_ALLOW_LIST` | — | comma-separated literal values or regex patterns (per `SKYBRIDGE_MASK_ALLOW_LIST_MATCH`) to never report as PII — suppress a known-safe recurring false positive without disabling an entity type or writing a custom recognizer |
| `SKYBRIDGE_MASK_ALLOW_LIST_MATCH` | `exact` | `exact` or `regex` — how `SKYBRIDGE_MASK_ALLOW_LIST` entries are interpreted; meaningless when the allow list is empty |
| `SKYBRIDGE_MASK_MODE` | `best-effort` | `best-effort` forwards a value unmasked if the remote masker errors/is unreachable (a masker outage never blocks a query); `strict` aborts the row/connection instead so unmasked content never reaches the client |

#### Custom PII recognizers

Presidio's built-in recognizer set can be extended with your own — either baked in statically, or
pushed dynamically from your control plane, mirroring the same static/dynamic split as the PII
overlay above.

| Variable | Default | What it does |
|---|---|---|
| `SKYBRIDGE_MASK_RECOGNIZERS_YAML` | — | inline YAML/JSON list of custom Presidio recognizers, passed through verbatim as `ad_hoc_recognizers` |
| `SKYBRIDGE_MASK_RECOGNIZERS_FILE` | — | path to a file with the same shape (takes priority if both are set) |
| `SKYBRIDGE_PII_RECOGNIZERS_URL` | — | control-plane endpoint to fetch org/driver/connection-role-scoped recognizers dynamically; hot-swaps `SKYBRIDGE_MASK_RECOGNIZERS_YAML`/`_FILE` in place |
| `SKYBRIDGE_PII_RECOGNIZERS_TOKEN` | `SKYBRIDGE_TOKEN` | bearer token for the fetch |
| `SKYBRIDGE_PII_RECOGNIZERS_POLL_SECONDS` | `60` | refresh interval |

#### Masking-outcome metrics

Pure-metadata counts (entity type, source layer, connection — **never** masked or raw values),
pushed to your control plane so a dashboard can show "how much PII did we mask, of what type."
Off by default.

| Variable | Default | What it does |
|---|---|---|
| `SKYBRIDGE_MASKING_METRICS_URL` | — (disabled) | `POST` endpoint metrics are pushed to |
| `SKYBRIDGE_MASKING_METRICS_TOKEN` | `SKYBRIDGE_TOKEN` | bearer token for the push |
| `SKYBRIDGE_MASKING_METRICS_PUSH_SECONDS` | `60` (floored) | push interval |

#### Path-scoped labels & AI classification

| Variable | Default | What it does |
|---|---|---|
| `SKYBRIDGE_PATH_LABEL_URL` | — (disabled) | control-plane pull/push base URL for confirmed + proposed path-scoped labels; unset leaves `PathOverlay` entirely out of the masking chain |
| `SKYBRIDGE_PATH_LABEL_TOKEN` | `SKYBRIDGE_TOKEN` | bearer token |
| `SKYBRIDGE_PATH_LABEL_POLL_SECONDS` | `60` (floored) | confirmed-label pull interval |
| `SKYBRIDGE_PATH_LABEL_PUSH_SECONDS` | `15` (floored) | proposed-label push interval |
| `SKYBRIDGE_POSTGRES_CATALOG_DSN` | — | dedicated, read-only Postgres credential (`postgres://user:pass@host:port`) the agent uses on a separate connection it owns for `pg_class`/`pg_namespace` lookups, resolving `PathOverlay`'s table identity for Postgres wire-proxy connections (see [Path-scoped labels](./REDACTION.md#path-scoped-labels-mask-pathoverlay)); unset leaves Postgres's `ObjectID` unresolved |
| `SKYBRIDGE_TRAFFIC_SAMPLER_LLM_ENDPOINT` | — (disabled) | enables a traffic-fed AI path-label classifier that samples free-text values straight out of live wire-proxy/`dbquery` traffic already flowing through this agent — no second, dedicated read-only DSN required (see `docs/AI_PATH_LABELLING_DESIGN.md` §5.2). Also requires `SKYBRIDGE_PATH_LABEL_URL` |
| `SKYBRIDGE_TRAFFIC_SAMPLER_LLM_API_KEY` | — | bearer/API key for the LLM endpoint above |
| `SKYBRIDGE_TRAFFIC_SAMPLER_LLM_CATEGORIES` | — | comma-separated PII category taxonomy the classifier is constrained to return |
| `SKYBRIDGE_TRAFFIC_SAMPLER_LLM_MIN_CONFIDENCE` | `0.5` | minimum confidence to accept a classifier proposal |
| `SKYBRIDGE_TRAFFIC_SAMPLER_MAX_FIELDS` | `10000` | max distinct `(ObjectID, FieldPath)` pairs buffered at once (LRU-evicted beyond this) |
| `SKYBRIDGE_TRAFFIC_SAMPLER_MAX_SAMPLES_PER_FIELD` | `20` | max sample values retained per field |
| `SKYBRIDGE_TRAFFIC_SAMPLER_SCAN_INTERVAL_SECONDS` | `300` | how often buffered fields are classified and proposed |

For scanning without live query traffic instead, see [The `labeller` role](#the-labeller-role) below.

#### Client TLS (encrypt native-client connections)

| Variable | Default | What it does |
|---|---|---|
| `SKYBRIDGE_CLIENT_TLS_CERT_FILE` / `_PEM` | — | server cert (Postgres) — enables terminating client TLS so a session token isn't sent in cleartext |
| `SKYBRIDGE_CLIENT_TLS_KEY_FILE` / `_PEM` | — | matching private key |
| `SKYBRIDGE_CLIENT_TLS_SELF_SIGNED` | `false` | dev: generate an ephemeral self-signed cert at startup (clients use `sslmode=require`) |

See ["Encrypt the client link"](#credential-handoff-the-client-never-holds-a-database-password) just below for why this matters most with credential injection enabled.

#### Credential handoff (the client never holds a database password)

| Variable | Default | What it does |
|---|---|---|
| `SKYBRIDGE_INJECT_CREDENTIALS` | `false` | enable credential handoff (clients present an opaque session token, not a DB password) |
| `SKYBRIDGE_CREDENTIAL_EXCHANGE_URL` | — | control-plane endpoint that swaps a session token for an upstream credential (`POST /your-control-plane/proxy-exchange`) |
| `SKYBRIDGE_CREDENTIAL_EXCHANGE_TOKEN` | `SKYBRIDGE_TOKEN` | bearer for the exchange call |
| `SKYBRIDGE_CREDENTIAL_EXCHANGE_PER_MIN` | unset (no limit) | caps exchange attempts per native-client IP per minute — without this, a client could try many guessed session tokens as the password with no local throttling |

**TL;DR:** instead of a real DB password, the client presents an **opaque session token** as its
password. The agent swaps that token with your control plane for a freshly-minted upstream
credential and logs in itself — the client never holds anything the database would accept directly.
Covers Postgres, MySQL, and Mongo. See `CredentialExchangeURL`'s shape in `CONTRACT.md` §3 to
implement the control-plane side.

```sh
SKYBRIDGE_DB_TYPE=postgres SKYBRIDGE_UPSTREAM=db.internal:5432 \
SKYBRIDGE_INJECT_CREDENTIALS=true SKYBRIDGE_TOKEN=<agent-service-bearer> \
SKYBRIDGE_CREDENTIAL_EXCHANGE_URL=https://app.example.com/your-control-plane/proxy-exchange \
go run ./cmd/skybridge agent
# client connects to the Skybridge listener (not the DB), any username, session token as password
```

| Protocol | What's different |
|---|---|
| **MySQL** | Needs client TLS + the client's cleartext-password plugin enabled (`mysql --enable-cleartext-plugin`) — MySQL's default auth is challenge-response, so the token can't be recovered otherwise. Needs upstream TLS too if the upstream negotiates `caching_sha2_password` full auth. |
| **Mongo** | Client must set `authMechanism=PLAIN` explicitly (`mongodb://user:<token>@host:port/?authMechanism=PLAIN`) — a driver won't auto-discover this the way MySQL's `AuthSwitchRequest` forces it. |

**Encrypt the client link:** the token rides in the password, so terminate client TLS
(`SKYBRIDGE_CLIENT_TLS_SELF_SIGNED=true` for a quick dev self-signed cert and `sslmode=require`; a
real `SKYBRIDGE_CLIENT_TLS_CERT_FILE`/`_KEY_FILE` for production and `sslmode=verify-full`). With
client TLS off, the agent logs a warning that the token travels in cleartext.

#### Upstream TLS (encrypt the agent → database hop)

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

| Variable | Default | What it does |
|---|---|---|
| `SKYBRIDGE_UPSTREAM_TLS` | `disable` | one of the modes above |
| `SKYBRIDGE_UPSTREAM_TLS_CA_FILE` / `_PEM` | system roots | trust roots used by `verify-ca` / `verify-full` (e.g. the RDS CA bundle) |
| `SKYBRIDGE_UPSTREAM_TLS_SERVER_NAME` | dial host | override the verified hostname / SNI sent to the upstream |

This is also what unblocks **`rds_iam` credential injection** — the RDS IAM auth token is only
accepted over a TLS connection. For RDS/Aurora, point the trust roots at the AWS RDS CA bundle:

```sh
SKYBRIDGE_DB_TYPE=postgres \
SKYBRIDGE_UPSTREAM=mydb.abc123.us-east-1.rds.amazonaws.com:5432 \
SKYBRIDGE_UPSTREAM_TLS=verify-full \
SKYBRIDGE_UPSTREAM_TLS_CA_FILE=/etc/ssl/rds/global-bundle.pem \
go run ./cmd/skybridge agent
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

#### Wire-agent mTLS (agent ↔ gateway, tunnel mode)

In tunnel mode, the agent normally dials the gateway using the plaintext `SKYBRIDGE_TOKEN` shared
secret. These variables switch it to mTLS instead — the agent enrolls once for a signed client
cert (or loads a pre-issued one) and presents that on every reconnect:

| Variable | Default | What it does |
|---|---|---|
| `SKYBRIDGE_WIRE_MTLS_ENROLL_URL` | — | control-plane origin used to bootstrap the first cert (e.g. `https://app.example.com`) |
| `SKYBRIDGE_WIRE_MTLS_ENROLLMENT_TOKEN` | — | one-time token for that first enroll call |
| `SKYBRIDGE_WIRE_MTLS_TLS_DIR` | — | directory that persists `ca.pem`/`client.crt`/`client.key` across restarts |
| `SKYBRIDGE_WIRE_MTLS_CA_BUNDLE_FILE` / `_PEM` | — | pins the enroll call's server TLS |
| `SKYBRIDGE_WIRE_MTLS_CLIENT_CERT_FILE` / `_PEM` | — | pre-issued client cert, skipping the enroll call entirely (e.g. injected from Secrets Manager) |
| `SKYBRIDGE_WIRE_MTLS_CLIENT_KEY_FILE` / `_PEM` | — | matching private key |
| `SKYBRIDGE_WIRE_MTLS_IDENTITY_SECRET_ARN` | — | mirrors the issued cert to this AWS Secrets Manager secret so a replaced task recovers its identity without a fresh enroll token — same mechanism as [Keeping mTLS identity alive across redeploys](#keeping-mtls-identity-alive-across-redeploys) below, applied to the wire tunnel identity |
| `SKYBRIDGE_WIRE_MTLS_IAM_AUTH` | `false` | presign `sts:GetCallerIdentity` with ambient AWS credentials instead of a static enrollment token — see [Fix 2](#keeping-mtls-identity-alive-across-redeploys) below; paired with `SKYBRIDGE_WIRE_MTLS_ENROLL_URL` |
| `SKYBRIDGE_TRUST_DOMAIN` | identity-specific default | cosmetic identity label placed in the CSR SAN; shared across this and the edge's connector/Studio identities |

Falls back to the plaintext bearer-token tunnel automatically when none of these are set.

#### Dynamic PII overlay (fetched from your control plane)

`SKYBRIDGE_PII_OVERLAY` / `SKYBRIDGE_PII_OVERLAY_FILE` are static. To keep native-client masking in
sync with column rules your own admin surface manages, point the agent at an HTTP endpoint instead:

```sh
SKYBRIDGE_ORG_ID=<org-uuid> \
SKYBRIDGE_TOKEN=<org-scoped-bearer> \
SKYBRIDGE_PII_OVERLAY_URL=https://app.example.com/your-control-plane/pii-overlay \
go run ./cmd/skybridge agent
```

The agent fetches `{ "columns": { "<column>": "<token>" } }` at startup and re-fetches every
`SKYBRIDGE_PII_OVERLAY_POLL_SECONDS`, hot-swapping the overlay in place (no restart). Your control
plane decides what "columns" contains — e.g. projecting a per-org PII schema into per-category
tokens (`email → [email]`, `ssn → [ssn]`), excluding business identifiers / operational columns. A
failed fetch leaves the last-known (or static `SKYBRIDGE_PII_OVERLAY`) rules intact. See
`internal/agent/overlay_source.go` for the exact request/response contract, including
`SKYBRIDGE_PII_OVERLAY_ORG_HEADER` if you need a header name other than the default
`X-Organization-Id`.

### Performance and tuning

#### Benchmarks

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

#### Tuning environment variables

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
| `SKYBRIDGE_STUDIO_MAX_SESSIONS` | `8` | Caps concurrent Query Studio dispatch sessions on one `edge`-role process. |
| `SKYBRIDGE_GW_CLIENT_CONN_PER_MIN` / `SKYBRIDGE_GW_ORG_CONN_PER_MIN` | unset (no limit); default `60`/min per client IP once `SKYBRIDGE_GW_CONTROL_PLANE_URL` is set | Gateway-side per-client / per-org *new*-connection-rate ceilings — the main throughput/abuse knobs on the `gateway` role in tunnel mode. |
| `SKYBRIDGE_GW_ORG_MAX_CONCURRENT_CLIENTS` | unset (no limit); default `1000` once `SKYBRIDGE_GW_CONTROL_PLANE_URL` is set | Caps how many client connections one org can have relayed *simultaneously* — unlike the rate limits above, this bounds the standing total, so one org holding many connections open indefinitely can't exhaust the gateway process's goroutines/file descriptors at every other org's expense. |
| `SKYBRIDGE_GW_AGENT_CONN_PER_MIN` | unset (no limit) | Caps agent *registration* attempts per client IP per minute — separate from the client-facing limits above; throttles how fast the agent listener's mTLS handshake (`SKYBRIDGE_GW_MTLS_CA_BUNDLE_PEM`, required — there is no bearer-token mode) can be probed. |

Everything else in `internal/config/config.go` (TLS, credential exchange, enrollment) is
correctness/security configuration, not a performance knob.

### Layout

```
cmd/skybridge           single binary; role picked by the first argument — agent (listener OR
                        tunnel mode) | gateway (agent endpoint + client listeners) | edge (call-home
                        transport + AWS reads + optional wire proxy) | labeller
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
wire engine (`internal/wire`) vs. exec-only support (`dbquery`/`dbexec`).

### The `edge` role

**TL;DR:** `skybridge edge` is the one thing a customer installs. It dials **out** (egress-only) to
the SaaS Connector Gateway, runs dispatched **read-only** AWS/k8s calls locally, and can co-host the
wire proxy in the same process. The LLM agent loop stays on the SaaS side.

```sh
SKYBRIDGE_EDGE_GATEWAY=gateway.example.com:8020 \
SKYBRIDGE_ORG_ID=org-123 SKYBRIDGE_EDGE_ID=edge-1 SKYBRIDGE_TOKEN=... \
SKYBRIDGE_AWS_REGION=us-east-1 \
go run ./cmd/skybridge edge
```

Or set a single `SKYBRIDGE_KEY` instead of `SKYBRIDGE_EDGE_GATEWAY`/`SKYBRIDGE_ORG_ID`/`SKYBRIDGE_TOKEN`
(the connector enrollment mint returns this as `customer_handoff.connector_key`):

```sh
SKYBRIDGE_KEY="skybridge://org-123:<enrollment-token>@gateway.example.com?edge_id=edge-1" \
SKYBRIDGE_AWS_REGION=us-east-1 \
go run ./cmd/skybridge edge
```

`SKYBRIDGE_KEY` only seeds defaults — any discrete `SKYBRIDGE_*` var above still overrides it, so
existing deployments and scripts keep working unchanged. The connector-gateway (`:7100`) and enroll
(`:7101`) ports are fixed by convention and derived from the key's bare host.

#### Auth: bearer token vs. mTLS

| Mode | Set | Behavior |
|---|---|---|
| Bearer (default) | `SKYBRIDGE_TOKEN` | Simple shared secret over TLS. Fine for a quick start. |
| mTLS (hardened) | `SKYBRIDGE_CA_BUNDLE_PEM`/`_FILE` + `SKYBRIDGE_ENROLLMENT_TOKEN` | The edge generates a keypair, calls `Enroll` once with the one-time token to get a signed client cert, then connects with mTLS. Preferred for production. |
| Reusable connector key (stateless) | `SKYBRIDGE_CONNECTOR_KEY` | Pure bearer mode, forced even if `SKYBRIDGE_CA_BUNDLE_PEM`/`_FILE`/`SKYBRIDGE_TLS_DIR` are also set — the edge never calls `certstore` (no disk read/write, no Secrets Manager). Unlike `SKYBRIDGE_TOKEN`'s default (which falls back to the same value as `SKYBRIDGE_ENROLLMENT_TOKEN` when unset), this is meant to be a genuinely long-lived, reusable value presented fresh on every boot — same model as hoop.dev's `HOOP_KEY`/StrongDM's `SDM_RELAY_TOKEN`. Use this when you want to run the edge as a plain Kubernetes `Deployment` with no `PersistentVolumeClaim` at all, at the cost of a static shared secret instead of mTLS's per-boot-derived identity. |

The issued cert is cached under `SKYBRIDGE_TLS_DIR` and reused on restart — no new token needed
until it's actually close to expiry. `SKYBRIDGE_CONNECTOR_KEY` skips this caching altogether by
design (see above).

#### Keeping mTLS identity alive across redeploys

**TL;DR:** on ephemeral compute (ECS/Fargate, EKS pods), a redeploy wipes `SKYBRIDGE_TLS_DIR` and
the enrollment token was already single-use — so a naive redeploy fails to re-enroll. Two fixes,
either works, and they compose:

| Fix | How | Set |
|---|---|---|
| **1. Cache the cert in Secrets Manager** | Edge mirrors its issued cert to a secret; a replacement task loads it instead of re-enrolling. | One of `SKYBRIDGE_IDENTITY_SECRET_ARN` (connector), `SKYBRIDGE_STUDIO_IDENTITY_SECRET_ARN` (Studio), `SKYBRIDGE_WIRE_MTLS_IDENTITY_SECRET_ARN` (wire tunnel) — needs `GetSecretValue`/`PutSecretValue` on the task's IAM role |
| **2. Skip the static token (AWS IAM auth)** | Edge presigns `sts:GetCallerIdentity` with its ambient AWS role and exchanges that for a fresh enroll token on every restart — nothing to consume, nothing to run out. Same pattern as Teleport's `iam` join / Vault's `aws` auth. | `SKYBRIDGE_IAM_AUTH=true` + `SKYBRIDGE_IAM_ENROLL_URL` (covers connector + Studio; the wire tunnel's equivalent is `SKYBRIDGE_WIRE_MTLS_IAM_AUTH` + `SKYBRIDGE_WIRE_MTLS_ENROLL_URL`) |

Fix 2 still checks Fix 1's cache first — a still-valid cached cert is always reused before minting a
new one. Requires server-side STS-replay verification on your control plane; see `internal/edgeiam`
for the request shape.

#### Reconnect resilience

Both call-home clients (`internal/edge/transport`, `internal/edge/studiotransport`) share one
reconnect design: jittered exponential backoff (1s doubling to 30s) that only resets after 60s of
stable connection, a higher backoff floor (120s) specifically for auth failures so a bad credential
doesn't get hammered every few seconds, and a cheap `PreConnect` pre-flight that lets a draining
gateway say "retry in N seconds" before a full stream handshake is attempted.

### Docs

- [`CONTRACT.md`](./CONTRACT.md) — the tunnel wire format and the gateway → control-plane HTTP
  session contract.
- [`deploy/TUNNEL_TESTING.md`](./deploy/TUNNEL_TESTING.md) — standing up the TUNNEL deployment
  shape locally and exposing it via ngrok for an external tester.
- All `SKYBRIDGE_*` settings are documented inline in `internal/config/config.go`.

### Contributing

Bug reports, feature requests, and PRs are welcome — see [`CONTRIBUTING.md`](./CONTRIBUTING.md) for
dev setup and guidelines, and [`SECURITY.md`](./SECURITY.md) to report a vulnerability privately.
This project follows the [Contributor Covenant](./CODE_OF_CONDUCT.md).

### License

Apache-2.0 — see [`LICENSE`](./LICENSE).
