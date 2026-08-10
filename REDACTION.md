# Redaction in Skybridge

This is a deep-dive on how Skybridge masks PII. For setup instructions, see the
[Quick start](./README.md#quick-start) and [Configure](./README.md#configure) sections of the
README; this document is about *how the masking pipeline actually works* and *why it's built the
way it is*.

## See it work

![Five scenarios: raw vs. masked SQL rows, free-text phone-number redaction, and raw vs. masked MongoDB documents](./examples/demo/redaction-demo.gif)

Five scenarios back to back, against a real running agent (no mocking):

1. **SQL row, raw** — `psql` straight to Postgres. `email`/`ssn` in plaintext.
2. **SQL row, masked** — the identical query through the Skybridge agent (a different port, same
   database). `email`/`ssn` are `[redacted]` — the column-overlay layer, matched by name.
3. **Free text, masked** — the `notes` column has *no* overlay rule for it, but the phone number
   embedded in the sentence is still redacted — the content-detection layer (`Remote`/Presidio)
   catches it by shape, not by column name.
4. **Non-SQL, raw** — `mongosh` straight to MongoDB. Same PII, plaintext, as a BSON document.
5. **Non-SQL, masked** — the identical query through a second Skybridge agent instance in front of
   MongoDB. `email`/`ssn` redacted inside the document — the masking chain is protocol-agnostic.

Reproduce it yourself:

```sh
./examples/demo/run-demo.sh up        # isolated demo Postgres + Mongo + Presidio + 2 agents
./examples/demo/demo-commands.sh      # runs all 5 scenarios and prints raw vs. masked output
./examples/demo/run-demo.sh down      # tear down
```

(The GIF itself was captured by running `demo-commands.sh` under
[`asciinema`](https://asciinema.org) and converting the recording to a GIF with
[`agg`](https://github.com/asciinema/agg): `asciinema rec --command ./examples/demo/demo-commands.sh
examples/demo/redaction-demo.cast && agg examples/demo/redaction-demo.cast
examples/demo/redaction-demo.gif`.)

## Where redaction happens

Every masking decision is made **inside the agent process**, before any byte crosses the network
boundary to the native client. There is no "redact after the fact" step and no reliance on the
client, the network, or a downstream proxy to enforce anything — a raw value is never even
serialized onto the wire if it would need masking. This is the load-bearing security property: an
attacker who can sniff the wire between the agent and the client only ever sees masked bytes.

```
 native client (psql/mysql/mongosh)
        ▲
        │  ONLY MASKED BYTES CROSS HERE
        │
 ┌──────┴───────────────────────────┐
 │  skybridge-agent (your network)  │
 │                                   │
 │  wire engine (postgres/mysql/    │
 │  mongo) decodes result rows      │
 │            │                     │
 │            ▼                     │
 │  masking chain (this doc)        │
 │            │                     │
 │            ▼                     │
 │  wire engine re-encodes rows     │
 └──────┬───────────────────────────┘
        │
        ▼
   your database
```

The wire engines (`internal/wire/postgres`, `internal/wire/mysql`, `internal/wire/mongo`) are
manual protocol parsers — they decode just enough of each result message to hand the masking chain
a row of column values, then re-encode whatever the chain returns. Anything a wire engine can't
parse is forwarded **unmasked, never corrupted** — the design deliberately favors "some real risk
of unmasked data on an edge case the parser doesn't understand yet" over "silently corrupt the
client's data," since corruption breaks applications in ways that are much harder to detect and
diagnose than a masking gap.

## The masking chain

Every result row/document passes through a **chain of maskers**, all implementing one interface:

```go
// internal/mask/mask.go
type Masker interface {
    MaskRow(ctx context.Context, cols []Column, row [][]byte) ([][]byte, error)
}
```

`Column` carries everything a masker might need to decide: `Name` (the column/field name as the
server reported it), `Text` (whether the value bytes are safe to inspect — binary-format values are
skipped, never guessed at), and `ObjectID`/`Path` (table/collection identity and resolved document
path — populated today only by the `dbquery` one-shot exec path; see
[Path-scoped labels](#path-scoped-labels-mask-pathoverlay) below).

The chain (`mask.Chain`, built by `mask.NewChain(...)`) runs each configured masker **in order**.
The contract that makes this composable rather than fragile:

> A miss at any layer is not fatal. The value falls through to the next layer unchanged. An
> unmasked value is *never* corrupted, only ever left as-is.

This means adding a new layer can only ever *add* coverage, never remove it or break an existing
one's behavior — a design choice that mattered a lot when `PathOverlay` (layer 3 below) was added
on top of the two layers that already existed in production.

### Layer 1 — `Remote` (content-shape detection)

`internal/mask/remote.go`. This is the **only layer that inspects the value itself** rather than
the field's name or position — which is exactly what makes it work uniformly on a structured
column (a `VARCHAR` that happens to contain an email) and on unstructured free text (a notes blob,
a JSON string column) alike. It has no notion of schema; its only question is "is this string
PII-shaped."

It's a thin HTTP client for any service implementing
[Presidio](https://github.com/data-privacy-stack/presidio)'s two-call shape:

1. `POST {analyzeURL}` with `{text, language, entities}` → a list of detected spans:
   `{entity_type, start, end, score}`.
2. `POST {anonymizeURL}` with `{text, analyzer_results, anonymizers}` → `{text: "<redacted>"}`.

Skybridge always requests the `replace` anonymizer with `new_value: "[redacted]"` by default (full
replacement, not partial masking) — see [Anonymizer strategies](#anonymizer-strategies-partial-vs-full-replace)
below for how to change that.

**Cost controls, because every text value is a network round trip:**

- `MinLen` (default 4 bytes) skips the call entirely for short values — numbers, short codes,
  single characters — since they're rarely worth a round trip and rarely contain real PII on their
  own.
- `Entities` restricts what the analyzer even looks for. Skybridge's own default (when
  `SKYBRIDGE_MASK_ENTITIES` is unset) is a **low-cost, regex/rule-based set**:
  `EMAIL_ADDRESS, PHONE_NUMBER, CREDIT_CARD, US_SSN, IP_ADDRESS, IBAN_CODE, CRYPTO` — a few
  milliseconds of CPU each, no ML model involved. Presidio's NER-backed types (`PERSON`,
  `LOCATION`, `ORGANIZATION`, `NRP`) require full spaCy inference per value and are prone to false
  positives on ordinary business data (a product name that looks like a person's name, a city name
  that's also a common word) — they're opt-in only, via `SKYBRIDGE_MASK_ENTITIES`.

**Failure handling — `SKYBRIDGE_MASK_MODE`:**

- `best-effort` (default): a transport error, non-200 response, or malformed response all fall
  through with the value **unmasked**. A detection *miss* (the call succeeded and found nothing) is
  never treated as an error in either mode — this only fires on the masker itself failing. The
  rationale: a Presidio outage should never take your database offline.
- `strict`: the same failures instead abort the row/connection, so unmasked content can never reach
  the client even during an outage — a posture other DLP-gated access proxies offer under their own
  equivalent strict mode. Use this when "silently pass through raw PII during an outage" is worse
  than "the query fails."

`Remote` is a no-op (skipped entirely, zero overhead) when `SKYBRIDGE_MASK_ANALYZE_URL` /
`SKYBRIDGE_MASK_ANONYMIZE_URL` aren't both set.

### Layer 2 — `PathOverlay` (path-scoped labels)

`internal/mask/pathoverlay.go`, backed by `internal/pathlabel/label` (a `Store` interface + an
in-memory `MemStore` reference implementation) and `internal/pathlabel/docpath` (nested-document
path walking). Live in the agent's chain whenever `SKYBRIDGE_PATH_LABEL_URL` is set — see
[Path-scoped labels](#path-scoped-labels-mask-pathoverlay) below for exactly what's live today vs.
what's still groundwork.

The problem this layer solves: a flat `column name → token` map (layer 3) can't express that
`order.total` and `user.total` — two columns/fields that happen to share a name — should carry
*independent* rules. `PathOverlay` looks up a label keyed on `(ObjectID, FieldPath)` — `ObjectID`
opaquely identifies a table/collection (e.g. `"org1:mongo:app:orders"`), `FieldPath` is the
resolved, index-erased document path (`profile.contact.email`, not just `email`).

Lookup order, on a miss:

1. Exact `(ObjectID, resolved path)` match.
2. Fall back to `(ObjectID, bare column name)` — same behavior a flat overlay would give.
3. Fall back to layer 3 (nothing found at all).

Only labels with `Source == manual` or `platform` ever redact live — a `Source == proposed` label
(something an automated PII scanner suggested) is **inert** until a human confirms it, so a
false-positive suggestion can never silently start redacting real data. A `do_not_mask` label still
defers to layer 1 having already run — a field marked safe-by-default can't suppress an actual
PII-shaped value that happens to land in it (layer 1 runs first in the chain, so this is automatic,
not a special case `PathOverlay` needs to implement).

### Layer 3 — `Overlay` (flat column-name map)

`internal/mask/overlay.go`. The original, simplest layer: a case-insensitive `column name →
replacement token` map. Configured via `SKYBRIDGE_PII_OVERLAY` (inline JSON),
`SKYBRIDGE_PII_OVERLAY_FILE` (a YAML/JSON file — see [Quick start](./README.md#quick-start)), or
fetched dynamically from a control-plane URL (`SKYBRIDGE_PII_OVERLAY_URL`) and hot-swapped in place
without a restart.

No path awareness — `total` under `order` and `total` under `user` share one rule, whichever was
defined last. This is intentionally kept as the *last*, most conservative layer: existing overlay
configs keep working unchanged even as `PathOverlay` picks up more precise cases above it, and it's
the cheapest possible check (an exact-match map lookup, no network call, no document walk) for
anyone who just wants "always redact this column."

**Structured vs. unstructured, in one sentence:** layer 1 (`Remote`) is what actually gives you
unstructured-text coverage; layers 2–3 are structured-schema shortcuts that skip the network round
trip for fields a human (or a confirmed detector proposal) has already labelled. Both kinds of
layer run on **every** row/document by default — there's no separate "structured mode" you have to
opt into.

## Path-scoped labels (`mask.PathOverlay`)

This section exists because it's the part of the pipeline most likely to confuse someone reading
the code: `PathOverlay` is wired into the live chain in `buildMaskerWithOverlay`
(`internal/agent/agent.go`) whenever `SKYBRIDGE_PATH_LABEL_URL` is set, backed by
`internal/pathlabel/remotestore.Store` (a control-plane-fetched `label.Store`, not the in-memory
`MemStore` reference implementation — see [Configuration](./README.md#configure) for
`SKYBRIDGE_PATH_LABEL_URL`/`_TOKEN`/`_POLL_SECONDS`/`_PUSH_SECONDS`). What's still missing is real
per-row table/collection identity for two of the three wire engines:

- **MySQL** (`internal/wire/mysql`) resolves real per-column table identity straight off the wire
  (schema + table name from the column-definition packet) as `"{org}:mysql:{schema}:{table}"` — so
  `PathOverlay` is fully effective for MySQL wire-proxy connections today.
- **Mongo** (`internal/wire/mongo`) resolves real per-reply collection identity by parsing each
  client `find`/`aggregate`/`getMore`/... command (read-only; the bytes it forwards are never
  mutated) to learn its target database/collection, then correlating that with the matching reply
  via the wire protocol's `requestID`/`responseTo` header fields, as `"{org}:mongo:{db}:{collection}"`
  — so `PathOverlay` is fully effective for Mongo wire-proxy connections today, including nested
  document paths (`profile.email`, matching `internal/pathlabel/docpath`'s convention). A command
  the engine doesn't recognize, or a reply whose request failed to parse, simply resolves to an
  empty `ObjectID` for that response — never an error.
- **Postgres** (`internal/wire/postgres`) resolves real per-row table identity too, but only when
  `SKYBRIDGE_POSTGRES_CATALOG_DSN` is configured — see
  [Postgres table-identity resolution](#postgres-table-identity-resolution) below for why this one
  needs an extra credential the other two engines don't. Unconfigured, it passes an empty
  `ObjectID` exactly as before this feature existed: `PathOverlay` treats that as "no label
  available," never as a lookup key of its own, so it's a guaranteed, safe no-op falling straight
  through to layer 3 (`Overlay`).
- `internal/edge/dbquery`'s one-shot exec path (`internal/edge/dbquery/mask.go`, part of the
  [`querystudio` build tag](./CLAUDE.md)) resolves `ObjectID`/`Path` for all four supported
  databases regardless of wire-proxy support — `maskRows` resolves per-query table identity as
  `"{org}:{driver}:{database}:{table}"` and sets `Path == Name` for flat SQL rows; `maskDocuments`
  walks Mongo documents **nested**, not flattened first (via `docpath.Walk`), so a
  `profile.contact.email` leaf gets its own resolved path independent of any top-level `email`
  column — see the [nested BSON example](#redaction-in-action) below.

So `PathOverlay` is fully online for all three wire engines today — the masker-chain wiring, the
control-plane-backed `Store`, and per-engine table/collection identity resolution are all live. The
only piece that's opt-in (rather than automatic like MySQL/Mongo) is Postgres's, because unlike the
other two it needs a dedicated credential — see below.

### Postgres table-identity resolution

Unlike MySQL (table name is a string in the column-definition packet) and Mongo (collection name is
a string in the client's own command document), Postgres's `RowDescription` message gives each
column only a numeric `(tableOID, attnum)` pair — never a name
(`internal/wire/postgres/postgres.go`'s `parseRowDescription`). Resolving `tableOID -> schema.table`
requires a catalog lookup (`SELECT relname, relnamespace::regnamespace::text FROM pg_class WHERE
oid = ...`) that the proxy has no other way to obtain, since it never rewrites or injects anything
into the client's own query stream.

**Why this can't reuse the client's connection.** If the agent issued that lookup on the same
backend connection it's proxying, it would insert an extra statement into whatever the client is
mid-way through — corrupting portal/cursor sequencing and, if the client is inside `BEGIN`,
potentially aborting the transaction on any error (Postgres aborts the whole transaction on any
statement failure). So `internal/wire/postgres/catalog.go`'s `CatalogResolver` opens and owns a
**second connection**, entirely separate from every client session, purely for these lookups.

**How it works.** `CatalogResolver.Resolve(ctx, database, tableOID)` is called from
`parseRowDescription` for every column whose `tableOID != 0` (0 means no backing table — a
computed/derived column — and always skips resolution, the same way MySQL's `objectID` treats an
empty `org_table`). One `catalogConn` is opened lazily per database name and kept for the process
lifetime; each resolved `(schema, table)` is cached indefinitely per `(database, tableOID)`, since
OIDs only change across a `DROP`/`CREATE`/`VACUUM FULL` cycle. The tableOID is a `uint32` parsed
straight off the wire — never a client-supplied string — so it's inlined directly into simple-Query
text with no injection surface, matching the precedent set by comparable access proxies' own
schema-introspection queries (also plain string-built SQL, relying on the same "these values aren't
attacker-controlled" property rather than the extended/parameterized protocol). Any failure — dial, auth, query error,
connection reset — makes `Resolve` return unresolved and drops the connection so the *next* lookup
redials, rather than surfacing an error to the client's own session: a catalog outage degrades to
this feature's pre-existing behavior (empty `ObjectID`, fallthrough to layer 3), never disrupts a
live query.

**Peeking the database name.** `pg_class`/`pg_namespace` are scoped per-database, so the resolver
needs to know which database the client's session is using. `Engine.Proxy` learns this by
`Peek`-ing (never consuming) the client's StartupMessage as it passes through — the same read-only
trick `negotiateStartup` already uses for SSL negotiation bytes — so the verbatim client->server
forwarding goroutine still relays every byte unchanged. `ProxyInject` already parses startup params
for credential injection, so it reuses that instead of a second peek.

**Credential.** The client's own login credential is deliberately not reused here — under
`SKYBRIDGE_INJECT_CREDENTIALS=true` it's a per-session credential minted for that one client
(`CONTRACT.md` §3), and even without injection, tying the catalog connection's lifetime to a client
session that can end at any time is the wrong shape for a cache meant to persist across sessions.
Following the same pattern other access proxies use for their own connection-level credential —
a single shared credential tied to the resource, not to each end-user's own login —
`SKYBRIDGE_POSTGRES_CATALOG_DSN`
configures a single dedicated, read-only credential (`postgres://user:pass@host:port`) independent
of the client's session and of `SKYBRIDGE_DB_*`. It only ever needs `SELECT` on `pg_catalog`.
Unset, this feature is off entirely — `internal/agent/clienttls.go`'s `buildPostgresCatalogResolver`
returns `nil`, and `Engine.objectIDFor` short-circuits to an always-empty `ObjectID`.

## Redaction in action

Same masking chain, four shapes of data. Left is what the database returns; right is what the
client actually receives.

**A SQL row (column overlay — matches by column name, no external service needed):**

```
 id |         email          | ssn                          id |       email       |     ssn
----+-------------------------+-----                →      ----+-------------------+-------------
 42 | alice@example.com      | 123-45-6789                 42 | [redacted]        | [redacted]
```

**A free-text column (content detection — `Remote`/Presidio catches PII regardless of column
name):**

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
independent rules despite sharing a field name; live in both the `dbquery` one-shot exec path and
the Mongo wire proxy today — see [Path-scoped labels](#path-scoped-labels-mask-pathoverlay) above):**

```
{ "profile": { "email": "jane@doe.com", "name": "Jane" }, "order": { "total": 42 } }
   →
{ "profile": { "email": "[redacted]", "name": "Jane" }, "order": { "total": 42 } }
```

Only `profile.email` is redacted — `order.total` and `profile.name` carry no label, so they fall
through every layer untouched, exactly as the fallthrough-on-miss contract guarantees.

## Anonymizer strategies (partial vs. full replace)

By default every detected span is fully replaced with the literal string `[redacted]`
(`SKYBRIDGE_MASK_ANONYMIZERS` unset → `{"DEFAULT":{"type":"replace","new_value":"[redacted]"}}`).
To keep partial information — e.g. mask an SSN's first five digits but keep the last four for
support-agent verification — set `SKYBRIDGE_MASK_ANONYMIZERS` to a Presidio "anonymizers" JSON
object keyed by entity type:

```json
{"US_SSN": {"type": "mask", "masking_char": "*", "chars_to_mask": 5, "from_end": false}}
```

This only affects layer 1 (`Remote`); the column-overlay layers (2–3) always do a full-value
replace with whatever token you configure — they have no notion of "partial" since they don't
inspect the value's internal structure.

## Testing this yourself

- `go test ./internal/mask/...` — the masking chain's own unit tests (each layer, plus
  `TestChainAppliesInOrder` for the fallthrough contract).
- `go test ./internal/edge/dbquery/... -tags querystudio` — the path-scoped resolution tests
  (`TestMaskDocuments_ResolvesNestedPaths`, `TestMaskDocuments_RedactsByPath`).
- `./examples/demo/run-demo.sh up` — the same live demo behind the GIF above, for poking at with
  your own queries.

See [`README.md`](./README.md#configure) for the full environment-variable reference and
[`CLAUDE.md`](./CLAUDE.md) for the broader architecture this pipeline sits inside.
