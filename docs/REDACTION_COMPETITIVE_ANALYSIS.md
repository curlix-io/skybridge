# Redaction: competitive analysis and improvement backlog

This is a point-in-time (2026-08) deep-dive comparing Skybridge's masking pipeline (`REDACTION.md`)
against hoop.dev and other open-source data-access/DLP projects, done to answer one question: **is
our redaction on par, and where should we actually invest next?** Findings are sourced from public
repos, docs, and code — cited inline so claims can be re-verified as these projects evolve.

## TL;DR

- Skybridge's core architectural bet — wire-protocol-native masking, done fully in the open-source
  tree, before bytes leave the customer's network — is **not duplicated by any other OSS project**
  we found. The closest competitor (hoop.dev) makes similar architecture claims but **ships the
  actual masking/DLP engine closed-source** (see [hoop.dev](#hoopdev-hoophqhoop)). Everyone else is
  either schema-declared/in-DB (`postgresql_anonymizer`), auth/audit-only with raw PII persisted in
  recordings (Teleport), or has no masking surface at all (pgbouncer/pgcat/ProxySQL, Vault).
- We are **on par or ahead** on: wire-protocol coverage (3 real proxies vs. hoop's closed one),
  path-scoped labels for nested documents (nothing comparable found anywhere else), fail-open/fail-
  closed transparency, and "never persist raw PII" as a first-class guarantee (contrast Teleport's
  session recordings, hoop's audit sink defaults).
- We are **behind** on: partial/format-preserving masking (postgresql_anonymizer's `anon.partial()`,
  Presidio's own `mask` operator), and cheap per-row round-trip cost for the `Remote` layer (Presidio
  now ships batch/structured analyze endpoints we don't use yet). Both are concrete, scoped
  follow-ups — see [Backlog](#improvement-backlog) below.

## hoop.dev (`hoophq/hoop`)

Repo: `github.com/hoophq/hoop` (MIT). Marketing framing: "ML-powered detection... not regex,"
wire-protocol-level masking, "the code that touches your data is code you can read."

**Architecture.** A layer-7 gateway model, not egress-only in the same sense as Skybridge: a
customer-side agent dials out to hoop's gateway, but the gateway is what native clients connect to
— inbound-facing from the client's perspective, mediated rather than agent-terminated the way
Skybridge's listener/tunnel modes are. DB proxying (`agent/controller/postgres.go`, `mysql.go`,
`mongodb.go`, `mssql.go`, `oracle.go`) is a thin wrapper that calls into `libhoop.NewDBCore(...)`.

**The masking engine is not in the OSS repo.** `libhoop` — the package every DB proxy call
actually dispatches into — is excluded via `.gitignore` and replaced in the public tree by a
no-op stub (`_libhoop/`) whose every method (`Postgres()`, `MySQL()`, `MongoDB()`, ...) immediately
errors with `"missing protocol hoop library for %v, contact your administrator"`. The real
protocol-parsing and masking logic ships only as a private/compiled dependency. This directly
contradicts the "code that touches your data is code you can read" claim in their own README.

**License-gated even when self-hosted.** `gateway/transport/plugins/dlp/dlp.go` checks
`ctx.OrgLicenseType == license.OSSType` and returns `codes.FailedPrecondition` /
`license.ErrDataMaskingUnsupported` — refusing to open the connection at all — if masking is
configured under an OSS-type license, **regardless of whether the DLP backend is GCP DLP or a
self-hosted Presidio instance**. So even "bring your own Presidio" doesn't unlock masking without a
paid license. The same license-gate pattern exists for guardrails (`_libhoop/guardrails.go`:
`ErrGuardRailsUnsupported` under OSS).

**Detection model**, from what config surface is public (`gateway/models/datamasking.go`): entity
detection via GCP DLP (deprecated in-product) or Presidio (`mspresidio`, same analyze/anonymize
shape Skybridge already uses), plus user-supplied custom regex entities with a score threshold.
Masking rules attach to a `ConnectionID`, i.e. **connection-scoped, not path-scoped** — we found no
equivalent of Skybridge's `(ObjectID, FieldPath)` lookup for nested documents anywhere in the repo.

**A genuinely open, separate effort exists but isn't wired into the product path**:
`hoophq/alcatraz` (standalone MIT PII-detection library: checksum-verified regex entities across 12
countries, optional ONNX NER) and `hoopinspect/pii/alcatraz` (a full masking engine built on it,
column-name or entity-type rules, `redact`/`mask`/`partial`/`hash` strategies) live in the OSS tree
— but neither `gateway/go.mod` nor `agent/go.mod` imports them; only an admin CLI does. It reads as
a parallel/newer initiative, not (yet) what runs in production.

**Failure modes.** `DLP_MODE` defaults to `best-effort` (same posture as Skybridge's default). Their
most candid documented split is in the experimental RDP PII guard
(`gateway/rdp/piigate.go`): analysis/parse errors fail **open** ("availability wins over
enforcement" for the PoC), but analyzer backlog/overflow fails **closed** (session killed) — a
useful precedent for us if `Remote` ever grows a backpressure case.

**Session recording persists raw PII by default.** `hoopinspect/audit/sink.go`'s
`SinkOptions.RedactStatements` is opt-in, added specifically because "some shops cannot store query
text at all, because literals embed the very PII the database is regulated for" — meaning the
*default* is to persist full statement text, including any PII in a literal. Their own
`hoopinspect/policy/pii.go` acknowledges the resulting gap directly: "a WHERE clause carrying a
customer's national ID leaks that ID into every query log... and response masking cannot undo
that." Skybridge has no query-text session-recording feature at all today, so this specific gap
doesn't apply to us — but it's a sharp argument for never adding one without redaction-by-default if
we ever do (tunnel/gateway session recording in `internal/gateway` currently only logs
lifecycle metadata, not query text or row values — keep it that way).

**Net comparison.** Skybridge ships strictly more of its actual masking implementation in the open
than hoop.dev does, has path-scoped labels where hoop has none, and doesn't license-gate the
core masking chain. hoop's stronger points: a broader protocol surface overall (SSH, RDP, k8s,
HTTP/gRPC, MCP — though most of that is orthogonal to PII masking specifically), and an interesting
prior-art pattern (`hoopinspect`'s `Reframer` abstraction, and its documented "masking is
response-side only, by design" stance) worth being aware of, not adopting wholesale.

## Other OSS/comparable projects

**`postgresql_anonymizer` / `anon` extension** (`gitlab.com/dalibo/postgresql_anonymizer`) — masks
strictly **in-database** via `SECURITY LABEL`s and rigged `search_path` views (static masking,
dynamic masking, or anonymous dumps). Content-blind: masking is entirely schema-declared, there's no
equivalent of our `Remote` content-shape layer. Its anonymization *operator* library is richer than
ours though — generalization, noise, shuffling, faking, and notably `anon.partial()` /
`anon.partial_email()` (`da******@gm******.com`) for partial/format-preserving redaction. Postgres-
only, and dynamic masking is documented as "known to be very slow," especially on joins involving a
masked/hashed key. Limitations documented upstream: one schema at a time for dynamic masking, rules
don't inherit across partitions, breaks GUI introspection tools for masked roles.

**Teleport (Database Access)** — no content-level masking whatsoever; it's an identity/RBAC + audit
proxy. Its own docs confirm session recordings capture query/result content
(protobuf-encoded, optionally AES-encrypted at rest). Encryption-at-rest is a different security
property than "never persisted" — anyone with decrypt/playback access sees raw PII. This is the
sharpest available contrast for our own "masking always happens before bytes leave the network, no
raw PII persisted anywhere for replay" claim in `REDACTION.md` — worth citing explicitly if we ever
write customer-facing comparison material.

**HashiCorp Vault (DB secrets engine)** — pure credential lifecycle (dynamic short-TTL credentials,
rotation), zero data-plane presence, zero masking. Directly analogous in scope to only our
`SKYBRIDGE_INJECT_CREDENTIALS` feature, not to the masking chain as a whole.

**pgbouncer / pgcat / ProxySQL** — all three are connection poolers/routers with no masking plugin
ecosystem at all (confirmed against README/wiki feature lists). This is a genuine white space: no
mature OSS pooler has ever grown a masking layer, which is part of why a purpose-built wire proxy
(Skybridge, or hoop's closed engine) exists as its own category rather than a pooler plugin.

**OPA / OPAL** — no OSS project found pairing policy-as-code engines directly with a wire-protocol
proxy for field-level redaction decisions. OPA/OPAL usage in data platforms skews toward
authorization (row/column access control), consulted by an app layer, not embedded in a native
protocol parser. Flagged as absence-with-caveat (search tooling was GitHub-only, not exhaustive).

**Cyral / Satori Cyber** — closed-source; both claim inline masking as part of broader DSPM/access
platforms. No verifiable implementation depth beyond marketing pages; not used as evidence for
technical claims, only noted for positioning language (hoop.dev's own README explicitly frames
itself against "PAM tools" — route/log only, no content parsing — and "DLP" — inspects data after
it's left the network — as a three-way category split. Worth reusing that framing in our own docs:
Skybridge is neither a PAM tool nor after-the-fact DLP, it's inline wire-protocol masking.).

**Microsoft Presidio** (already an integrated dependency via our `Remote` layer,
`internal/mask/remote.go`) — the upstream project has moved since we last touched this doc:
- `presidio-structured` (`PandasAnalysisBuilder`/`JsonAnalysisBuilder`) and the core
  `BatchAnalyzerEngine` batch many texts/columns through one `analyze` call instead of one round
  trip per value — directly relevant to our per-row-per-field call pattern in `remote.go`. See
  [Backlog](#improvement-backlog).
- The `mask` anonymizer operator (char-count partial masking, `chars_to_mask`/`from_end`) is the
  same partial-masking primitive `postgresql_anonymizer` and hoop's `alcatraz` masker both offer natively
  and we currently don't expose as a first-class `Overlay`/`PathOverlay` mode (we only get it
  through `SKYBRIDGE_MASK_ANONYMIZERS` on the `Remote` layer today — see REDACTION.md's
  ["Anonymizer strategies"](../REDACTION.md#anonymizer-strategies-partial-vs-full-replace) section).
- `allow_list`/`allow_list_match`/`regex_flags` are now first-class REST API params — lets an
  operator suppress known-false-positive values without maintaining a full custom recognizer.
- `hash` anonymizer is now **salted by default** (breaking change upstream) — if we ever want
  referential-integrity-preserving hashing (same input -> same masked output across rows, for joins
  on a masked column), the salt itself must be handled with the same "never log a raw value or
  secret" discipline as everything else in `CLAUDE.md`'s security checklist.
- Country-specific recognizers (SG/AU/IN/ES) are now disabled by default upstream to cut false
  positives — worth a doc note in our `SKYBRIDGE_MASK_ENTITIES` guidance if/when we point users at
  non-default entity sets.

**DataHub, Bytebase** — catalog/governance and schema-change tools respectively; metadata
classification or change management, not live-traffic masking. Not comparable, flagged only.

## Improvement backlog

Two concrete, scoped items came out of this review. Neither changes the fallthrough/never-corrupt
contract or any layer ordering — both are additive.

1. **Batch the `Remote` layer's analyze calls — done.** `internal/mask/remote.go`'s `MaskRow` now
   collects every eligible free-text column in a row and sends them as a single batched
   `POST /analyze` call (Presidio's stock analyzer server accepts `"text"` as a JSON array and
   returns a parallel array of per-item span lists — confirmed by reading `presidio-analyzer/app.py`
   directly). `POST /anonymize` has no equivalent batch input upstream, so it's unchanged: still one
   call per column that actually had a detection, same as before. Cross-row batching (buffering
   multiple rows before calling `MaskRow`) and doing anonymization locally in Go (to skip the
   `/anonymize` round trip entirely) were both considered and explicitly left out of scope — the
   former conflicts with the wire engines' one-row-at-a-time streaming model, the latter risks
   correctness drift from Presidio's own anonymizer operator semantics.
2. **Partial/format-preserving masking as a first-class `Overlay`/`PathOverlay` mode.** Right now
   layers 2–3 only do full-value token replacement (`REDACTION.md`: "the column-overlay layers
   (2–3) always do a full-value replace... they have no notion of partial"). Presidio's `mask`
   operator, `postgresql_anonymizer`'s `anon.partial()`, and hoop's `alcatraz` `partial` strategy all
   converge on the same primitive: keep N chars (usually from one end), mask the rest. Adding this to
   `PathOverlay`/`Overlay` (not just the `Remote` layer, which already gets it indirectly via
   `SKYBRIDGE_MASK_ANONYMIZERS`) would close a real, cheap-to-close gap for the common
   "show last 4 digits of an SSN/card to a support agent" case that currently requires going through
   Presidio at all just to get partial masking on a *known* column.

Both are backlog items, not committed work — raised here for prioritization, not implemented as
part of this doc.
