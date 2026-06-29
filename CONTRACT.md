# Skybridge wire contracts

Skybridge has three boundaries. The tunnel transport is intentionally small and stdlib-only so the
agent and gateway build offline with no third-party dependencies; the two HTTP contracts are plain
JSON over `net/http`.

1. **Agent ⇄ Gateway tunnel** — a length-prefixed framed transport that multiplexes many
   native-client sessions over one egress connection.
2. **Gateway → Control plane** — an optional HTTP contract for recording native-session lifecycle
   in an external system of record.
3. **Agent → Control plane (credential exchange)** — an optional HTTP contract that swaps a
   client-presented session token for a freshly-minted upstream credential (credential handoff).

---

## 1. Tunnel transport (agent ⇄ gateway)

The agent dials **out** to the gateway and holds one long-lived connection. The gateway multiplexes
native-client sessions over it as logical streams. Masking always happens at the agent, so only
already-masked bytes ever cross this boundary.

### Frame header (big-endian, fixed 12 bytes)

```
offset size field
0      2    magic    'S' 'B' (0x53 0x42)
2      1    version  current = 1
3      1    type     1=control  2=open  3=data  4=close
4      2    flags    reserved (0)
6      4    connID   logical stream id (0 for control)
10     2    length   payload byte length (0..MaxPayload)
```

Payload follows the header. `MaxPayload` bounds a single frame; larger writes are split across
multiple `data` frames.

### Frame types

| Type      | connID | Payload                                  | Meaning                                  |
|-----------|--------|------------------------------------------|------------------------------------------|
| `control` | 0      | JSON `Control`                           | session-level messages (see below)       |
| `open`    | new    | JSON `OpenMeta`                          | gateway opens a new stream to a target   |
| `data`    | stream | opaque bytes                             | bidirectional stream payload             |
| `close`   | stream | empty                                    | half/ full close of a stream             |

### Control messages (JSON)

`control` frames carry a `Control` object discriminated by `kind`:

| kind           | direction        | fields                                  |
|----------------|------------------|-----------------------------------------|
| `register`     | agent → gateway  | `agent_id`, `org_id`, `token`, `targets[]` |
| `register_ack` | gateway → agent  | `ok`, `error?`                          |
| `heartbeat`    | agent → gateway  | `agent_id`                              |

`targets[]` entries are `{ "name", "addr", "db_type" }` where `db_type ∈ {postgres, mysql, mongodb}`,
plus optional attribution fields `{ "resource_role_id"?, "actor_email"? }`. A target usually fronts a
single Studio resource role; declaring `resource_role_id` lets the gateway attribute relayed sessions
to that role (and, via the role's native-client credential lease, to its owner) instead of recording
them unattributed. `actor_email` is only meaningful for a target dedicated to one user.

`OpenMeta` (the `open` frame payload) is `{ "target": "<name>" }`; the agent resolves it to a
configured target and dials the upstream database.

### Compatibility

The header is fixed and `version`-tagged. Receivers MUST reject frames whose magic does not match and
SHOULD reject unknown versions. New fields are added to the JSON control messages in a
backward-compatible way (additive, optional).

### Transport security

This module implements the framing only; it does not mandate a transport. In production, wrap the
gateway's agent endpoint with mTLS (e.g. pass a `tls.NewListener` to `Gateway.ListenAgents`) so the
egress connection is mutually authenticated and encrypted.

---

## 2. Session recording (gateway → control plane)

Optional. When the gateway is configured with a control-plane URL it reports the lifecycle of each
relayed native session over HTTP. The control plane remains the **single writer** of the durable
session store; the gateway holds no database driver.

Base path defaults to `/api/v1/data-studio/studio/native-sessions` and is configurable
(`SKYBRIDGE_GW_SESSION_PATH`).

### Start

```
POST {baseURL}{basePath}
Authorization: Bearer <token>
Content-Type: application/json

{
  "agent_id":         "agent-1",
  "organization_id":  "<tenant id>",
  "target":           "prod-users",
  "db_type":          "postgres",
  "client_addr":      "10.0.0.5:54321",
  "resource_role_id": "<role id>",          // optional; attributes the session to a resource role
  "actor_email":      "owner@example.com",  // optional; only when the target is owned by one user
  "started_at":       "2026-01-01T00:00:00Z"
}
```

Response `201`:

```json
{ "id": "<session id>" }
```

### End

```
POST {baseURL}{basePath}/{id}/close
Authorization: Bearer <token>
Content-Type: application/json

{
  "ended_at":    "2026-01-01T00:05:00Z",
  "bytes_up":    1024,
  "bytes_down":  2048,
  "status":      "executed",
  "db_username": "curlix_s_9f2a",  // optional; login sniffed from the handshake (see Attribution)
  "error":       ""
}
```

Response `200`.

### Semantics

- Recording is **best-effort** from the relay's perspective: a reporting failure must never break or
  delay a live database session.
- An empty session id on close is a no-op (the start call never produced one).
- All times are RFC 3339 / ISO 8601 UTC.

---

## 3. Credential exchange (agent → control plane)

Optional. Used only when credential injection is enabled (`SKYBRIDGE_INJECT_CREDENTIALS=true`). After
the agent terminates a native client's login (the client presented an opaque curlix **session token**
as its password), it exchanges that token for a freshly-minted upstream credential. The agent — not
the gateway — performs this exchange, so it works identically in listener and tunnel mode and the
gateway stays a pure byte relay. The minted secret exists in clear only in this response and never
reaches the native client.

```
POST {SKYBRIDGE_CREDENTIAL_EXCHANGE_URL}      (default control-plane route:
Authorization: Bearer <token>                  /api/v1/data-studio/studio/native-access/proxy-exchange)
Content-Type: application/json

{
  "session_token":      "<token the client presented as its password>",
  "requested_user":     "alice",     // optional; the "user" the client asked for (informational)
  "requested_database": "appdb"      // optional; the database the client asked to connect to
}
```

Response `200`:

```json
{
  "username": "curlix_s_ab12cd",     // upstream DB role to authenticate as
  "password": "…",                    // minted secret (used only to originate upstream auth)
  "database": "appdb"                 // optional; overrides the client's requested database
}
```

Non-2xx responses carry a `{"detail": "..."}` reason; the agent maps the failure to a clean
authentication error shown to the native client (e.g. a Postgres `ErrorResponse`, SQLSTATE `28000`).

### Semantics

- The control plane **re-authorizes** the bound actor at exchange time (access may have been revoked
  since the token was minted) and records a credential **lease** so the minted credential is torn
  down on session end / by the sweep, exactly like the in-app execute path.
- The exchange is gated by `CURLIX_STUDIO_CREDENTIAL_BROKER_ENFORCE`; the token is short-lived and
  may be exchanged multiple times within its window (native clients open several pooled connections).
- Engines that do not implement injection (currently Mongo) ignore this contract and forward the
  client's own auth verbatim. Postgres and MySQL implement it. MySQL additionally requires client TLS
  and the client using the `mysql_clear_password` plugin (its default auth is challenge-response, so
  the token cannot otherwise be recovered).
- The minted credential is presented to the database over whatever upstream transport the agent
  negotiates. When the broker returns an `rds_iam` token (or the database otherwise requires
  encryption), the agent must run with upstream TLS (`SKYBRIDGE_UPSTREAM_TLS`); the IAM token is only
  accepted by RDS over a TLS connection.

### Attribution

A relayed session is attributed to its owner so it appears in that user's session list (not just to
admins). The gateway never re-runs end-user auth, so attribution flows from what it can observe:

1. **By resource role (at start):** `resource_role_id` on the start report. The control plane resolves
   the owner from the role's active native-client credential lease when **unambiguous** (exactly one
   holder).
2. **By login username (at close):** `db_username` on the close report. The gateway sniffs the login
   from the (unmasked) client→upstream handshake — Postgres `StartupMessage` / MySQL
   `HandshakeResponse41`; other protocols yield none. Ephemeral brokers mint a **unique** login per
   grant, so this resolves the owner deterministically even when several users share one role — the
   case (1) must leave unattributed. `actor_email` on the start report (single-owner targets) short-
   circuits both.

When none resolve, the session is recorded honestly **unattributed** (admin-visible).
