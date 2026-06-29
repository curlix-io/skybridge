# Skybridge

**Skybridge** is a small Go data plane for **governed native database access**. An egress-only agent
sits in front of your database, speaks the native client protocols (`psql`, `mysql`, `mongosh`, app
drivers), and **masks PII at the source** — so raw rows never leave your network.

- Stdlib-only wire-proxy core — manual protocol parsing + masking, no third-party deps.
- Content-aware masking — pluggable remote masker + a column overlay you define.
- Anything an engine can't parse is forwarded **unmasked, never corrupted**.
- One edge binary (`skybridge-edge`) also dials home for **live read-only AWS reads**, so everything
  that must run inside your network is a single install.

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
- **Edge** — `skybridge-edge` dials **out** to the SaaS Connector Gateway and runs dispatched
  **read-only tool calls** locally — chiefly live AWS reads against your account — and can co-host the
  wire proxy in the same process. One install for everything that must run inside your network. See
  [The `skybridge-edge` binary](#the-skybridge-edge-binary) below.

## Quick start

Put the agent in front of your database and point a native client at it. Pick one:

**Run with Go** (needs Go ≥ 1.26, no build step):

```sh
SKYBRIDGE_UPSTREAM=db.internal:5432 \
SKYBRIDGE_PII_OVERLAY='{"email":"[redacted]","ssn":"[redacted]"}' \
go run ./cmd/skybridge-agent
```

**Run with Docker**:

```sh
cd deploy
SKYBRIDGE_UPSTREAM=db.internal:5432 docker compose up
```

Then connect a native client through the agent (listening on `:15432` by default):

```sh
psql "postgres://user:pass@localhost:15432/appdb"
```

That's it — result rows are masked before they reach the client. With no mask config the agent is a
transparent, governed passthrough.

## Configure

Set these as environment variables (full list in `internal/config/config.go`):

| Variable | Default | What it does |
|---|---|---|
| `SKYBRIDGE_UPSTREAM` | — | upstream database `host:port` (**required**) |
| `SKYBRIDGE_DB_TYPE` | `postgres` | `postgres`, `mysql`, or `mongodb` |
| `SKYBRIDGE_LISTEN` | `:15432` / `:13306` / `:27018` | local address clients connect to |
| `SKYBRIDGE_PII_OVERLAY` | — | JSON `{ "column": "[redacted]" }` map you define (static) |
| `SKYBRIDGE_PII_OVERLAY_URL` | — | control-plane endpoint to fetch the org's projected overlay (`GET /api/v1/data-studio/studio/native-access/pii-overlay`); enables dynamic, hot-swapped masking |
| `SKYBRIDGE_PII_OVERLAY_TOKEN` | `SKYBRIDGE_TOKEN` | bearer token for the overlay fetch |
| `SKYBRIDGE_PII_OVERLAY_POLL_SECONDS` | `60` | overlay refresh interval (min 15s; `-1` = fetch once at startup) |
| `SKYBRIDGE_MASK_ANALYZE_URL` | — | enable content masking: any `POST /analyze` service |
| `SKYBRIDGE_MASK_ANONYMIZE_URL` | — | …paired `POST /anonymize` service |
| `SKYBRIDGE_INJECT_CREDENTIALS` | `false` | enable credential handoff (clients present a curlix session token, not a DB password) |
| `SKYBRIDGE_CREDENTIAL_EXCHANGE_URL` | — | control-plane endpoint that swaps a session token for an upstream credential (`POST /api/v1/data-studio/studio/native-access/proxy-exchange`) |
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
presents an **opaque curlix session token as its password**; the agent terminates that login locally,
exchanges the token with the control plane for a freshly-minted, short-lived upstream credential, and
**originates its own upstream authentication** with it (Postgres: trust / cleartext / md5 /
SCRAM-SHA-256; MySQL: mysql_native_password / caching_sha2_password). The client therefore never holds
a credential the database would accept directly, and result rows are still masked inline.

```sh
SKYBRIDGE_DB_TYPE=postgres \
SKYBRIDGE_UPSTREAM=db.internal:5432 \
SKYBRIDGE_INJECT_CREDENTIALS=true \
SKYBRIDGE_TOKEN=<agent-service-bearer> \
SKYBRIDGE_CREDENTIAL_EXCHANGE_URL=https://app.example.com/api/v1/data-studio/studio/native-access/proxy-exchange \
go run ./cmd/skybridge-agent
```

The user first mints a session token from curlix
(`POST /api/v1/data-studio/studio/connections/{role_id}/proxy-session`), then in pgAdmin/psql/DBeaver points the
client at the **Skybridge listener** (not the database), uses any username, and pastes the session
token **as the password**. Injection covers **Postgres** and **MySQL**; Mongo falls back to verbatim
auth passthrough (logged at startup).

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
SKYBRIDGE_CREDENTIAL_EXCHANGE_URL=https://app.example.com/api/v1/data-studio/studio/native-access/proxy-exchange \
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

### Dynamic PII overlay (from Administration → PII)

`SKYBRIDGE_PII_OVERLAY` is a static map. To keep native-client masking in sync with the column rules
you define in **Administration → PII**, point the agent at the control plane instead:

```sh
SKYBRIDGE_ORG_ID=<org-uuid> \
SKYBRIDGE_TOKEN=<org-scoped-bearer> \
SKYBRIDGE_PII_OVERLAY_URL=https://app.example.com/api/v1/data-studio/studio/native-access/pii-overlay \
go run ./cmd/skybridge-agent
```

The agent fetches `{ "columns": { "<column>": "<token>" } }` at startup and re-fetches every
`SKYBRIDGE_PII_OVERLAY_POLL_SECONDS`, hot-swapping the overlay in place (no restart). Curlix projects
the org's merged PII schema into per-category tokens (e.g. `email → [email]`, `ssn → [ssn]`),
excluding business identifiers / operational columns. A failed fetch leaves the last-known (or static
`SKYBRIDGE_PII_OVERLAY`) rules intact. Note the wire overlay does **full-cell** replacement only; it
cannot do the partial / value-shape redaction the in-process execute pipeline performs, so token
counts differ between the two paths by design.

## Layout

```
cmd/skybridge-agent     egress agent: listener OR tunnel mode
cmd/skybridge-gateway   relay gateway: agent endpoint + client listeners
cmd/skybridge-edge      unified edge: call-home transport + AWS reads + optional wire proxy
internal/wire           wire engines: postgres, mysql, mongo
internal/mask           masking pipeline: remote masker + column overlay
internal/tunnel         egress multiplexed transport
internal/gateway        agent registry + relay + optional session recording
internal/edge           edge tool dispatch: envelope, read-only AWS policy, executor
internal/edge/transport egress-only gRPC call-home client (Connect/serve/reconnect)
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

**Auth.** By default the edge uses a bearer token over TLS (`SKYBRIDGE_TOKEN`). For the hardened
path, provide a CA bundle (`SKYBRIDGE_CA_BUNDLE_PEM` or `_FILE`) and a one-time
`SKYBRIDGE_ENROLLMENT_TOKEN`: the edge generates a keypair, calls `Enroll` to get a client cert,
persists it under `SKYBRIDGE_TLS_DIR`, and connects with mTLS — re-enrolling automatically before
expiry.

## Docs

- [`CONTRACT.md`](./CONTRACT.md) — the tunnel wire format and the gateway → control-plane HTTP
  session contract.
- All `SKYBRIDGE_*` settings are documented inline in `internal/config/config.go`.

## License

Apache-2.0 — see [`LICENSE`](./LICENSE).
