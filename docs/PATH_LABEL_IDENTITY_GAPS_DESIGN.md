# Closing two path-label identity gaps — design doc

Status: **Draft / RFC**. Two related, currently-real gaps in how `PathOverlay`
(`internal/mask/pathoverlay.go`) resolves column identity and type, found while tracing how a
customer's redact/don't-redact decision (set via the curlix UI, landing as a `manual`-sourced
`label.Label`) actually reaches a live query. Both stem from the same root cause: the wire engines
resolve *some* of a column's real schema identity today, but not all of it.

## 1. Gap A — column aliasing breaks path-label lookup (false negative)

### Problem

A customer confirms a label on `(ObjectID, "email")` via curlix's UI. A client runs
`SELECT email AS contact_info FROM users`. Today:

- **MySQL** (`internal/wire/mysql/mysql.go`'s `columnIdentity`) already parses the column-definition
  packet's 6th lenenc string, `org_name` — the real, unaliased column name — but discards it
  (`// org_name (6th lenenc string) — skip, not needed here.`). `mask.Column.Name`/`Path` are set
  from the 5th lenenc string (`name`, the possibly-aliased display name) instead.
- **Postgres** (`internal/wire/postgres/postgres.go`'s `parseRowDescription`) parses `colAttr` (the
  column's `attnum` within its table) off the wire at bytes `off:off+2`, but never uses it — `Name`/
  `Path` are set straight from `RowDescription`'s own column-name field, which **is** the
  post-`AS`-alias name PostgreSQL puts on the wire; there is no unaliased name available anywhere
  else in `RowDescription` itself.

Either way, `PathOverlay.lookupToken` looks up `(ObjectID, "contact_info")` — misses the exact-path
match on `"email"`, misses the bare-key fallback too, and falls through unmasked. **The customer's
explicit redact decision silently fails to apply**, with no error, no log line, nothing — this is
the class of gap `PathOverlay`'s fallthrough-on-miss contract treats identically to "no label was
ever set for this path," which is indistinguishable from "a label exists but the lookup key was
wrong."

This is a false negative (under-redaction), not a corruption risk — arguably more urgent than
Gap B below, since a customer who confirmed a redact decision has a reasonable expectation it holds
regardless of how a client happens to phrase its query.

### Fix

**MySQL** — already has everything it needs on the wire. `columnIdentity` already computes
`orgTable` (used for `ObjectID` resolution, `s.objectID(schema, orgTable)`); the same treatment for
`org_name` closes this gap:

```go
// columnIdentity — decode org_name (6th lenenc string) instead of skipping it.
orgNameSpan, ok := lenEncStrSpan(p, off)
...
orgName := lenEncStr(p, off) // NEW: keep this instead of discarding
off += orgNameSpan
```

Then in the caller (`mysql.go:409`):

```go
mask.Column{Name: name, Path: orgName, ObjectID: s.objectID(schema, orgTable), Text: true, FreeText: freeText}
```

`Path` becomes the real, unaliased column name (matching how `Path` already differs from `Name` for
nested Mongo fields — this is the same "Name is display, Path is what a label is actually keyed on"
split, just for a different reason). `Name` stays the aliased display name, since some existing
`Overlay` (flat column-name map) configs may have been written against display names in practice —
changing `Name`'s meaning retroactively could regress those; changing what `PathOverlay` keys its
*lookup* on (`Path`, per `pathoverlay.go:96-98`'s `path := col.Path; if path == "" { path = col.Name }`)
does not require touching `Overlay` at all.

**Postgres** — `colAttr` alone isn't a name; it needs a `pg_attribute` lookup, the same shape
`CatalogResolver` already does for `pg_class`/`pg_namespace`:

```sql
SELECT attname FROM pg_attribute WHERE attrelid = $1 AND attnum = $2
```

Extend `CatalogResolver` with a second cached lookup, `ResolveColumn(ctx, database, tableOID,
attnum) (columnName string, ok bool)`, using the same per-database `catalogConn`, same
indefinite-cache-until-DDL-change posture, same "any failure degrades to unresolved, never disrupts
the client's session" contract as `Resolve` (schema/table) already has (`REDACTION.md`'s "Postgres
table-identity resolution" section documents this precedent in full). `parseRowDescription` gains a
second resolver callback (or `objectIDResolver` grows a second return value) and sets `Path` to the
resolved real name, `Name` to the wire's own (possibly aliased) name — same split as MySQL above.

Cost: one additional `pg_attribute` query per *distinct* `(tableOID, attnum)` pair, cached
indefinitely just like the table lookup — this is not per-row, only per newly-seen column shape, so
it does not add meaningful overhead to steady-state traffic.

### Non-goals

- Resolving aliases for **computed/derived columns** (`SELECT UPPER(email) AS x`) — Postgres reports
  `tableOID == 0`/`attnum == 0` for these (no backing column at all), which already, correctly,
  skips resolution entirely (same as today) — there is no "real name" to resolve to, since the value
  is no longer literally the column's contents. This is unchanged: a computed column with no
  backing table already falls through to `Overlay`/unmasked, same as an unresolvable object today.
- Retroactively changing what `Overlay`'s flat column-name map keys on — `Name` (the aliased/display
  name) keeps its current meaning; only `PathOverlay`'s lookup key changes to prefer the real name.

## 2. Gap B — typed non-text columns can't be redacted at all (feature gap, not corruption)

### Problem

`mask.Column.FreeText bool` (`internal/mask/mask.go:31-41`) is the *only* signal a `Masker` has
about a column's type shape, and it's binary: free-text-eligible or not. `PathOverlay.MaskRow`
(`pathoverlay.go:59`) and `Overlay.MaskRow` (`overlay.go:64`) both skip any column where
`!cols[i].FreeText` — unconditionally, regardless of whether a *confirmed* label exists for it. This
is deliberate and correct as far as it goes: substituting the string `"[redacted]"` into a wire slot
the client will type-decode as, say, a `timestamptz` corrupts the response (`psycopg2` raising
`unable to parse date`) rather than just over-redacting — a documented, real incident
(`postgres.go`'s `nonFreeTextTypeOIDs` comment cites the exact false-positive that motivated this
guard).

The consequence: if a customer's curlix UI lets them mark, say, a `date_of_birth timestamptz`
column or a `ssn` column stored as `bigint` for redaction, **that confirmed label is accepted and
stored, but never actually redacts anything** — `MaskRow` skips the column before the label lookup
even runs. No error surfaces anywhere; the customer's decision is silently inert. This is a feature
gap (a real, known limitation, already flagged in both wire engines' comments), not a corruption
risk — the current behavior is the *safe* failure mode, just an incomplete one.

### Fix

Replace the binary `FreeText bool` with an enum that preserves enough type information to pick a
**type-valid replacement value** instead of a string token, for columns where a confirmed label
requests redaction:

```go
// TypeKind classifies a column's wire type shape for masking purposes — a superset of the
// FreeText/not-FreeText split, kept so a confirmed label can still redact a typed column using a
// type-valid placeholder rather than being unconditionally skipped.
type TypeKind int

const (
    TypeText    TypeKind = iota // free-form text — content detectors run here (equivalent to today's FreeText=true)
    TypeDate                    // date/time/timestamp/timestamptz/interval
    TypeNumeric                 // int/float/decimal/numeric
    TypeBool
    TypeUUID
    TypeJSON    // structured but not prose — Remote still inspects it today (see mask.Column doc), unaffected
    TypeBinary  // uuid/bytea-shaped fixed binary, distinct from arbitrary BLOBs Text=false already excludes
    TypeUnknown // protocol drift / unrecognized type OID — treated as TypeText, matching today's fail-open default
)
```

`Column.FreeText bool` becomes a computed convenience (`col.TypeKind == TypeText`) rather than a
stored field, so every existing caller that only ever set `FreeText: true` unconditionally
(Mongo, MySQL/dbquery callers with no schema type, k8sexec) needs no change beyond a mechanical
rename if any code reads the field directly — `grep` shows only `overlay.go`/`remote.go`/
`pathoverlay.go` read it, all inside this package.

Both wire engines already have the exact classification needed — `nonFreeTextTypeOIDs` (Postgres)
and `nonFreeTextColumnTypes` (MySQL) already partition types into "safe to scan as text" vs. not;
mapping each OID/type-byte to a specific `TypeKind` instead of a bare bool is a mechanical
extension of a table that already exists, not new detection logic:

```go
var postgresTypeKinds = map[uint32]mask.TypeKind{
    16: mask.TypeBool, 19: mask.TypeText /* name: catalog identifier, never PII */, 20: mask.TypeNumeric,
    21: mask.TypeNumeric, 23: mask.TypeNumeric, 26: mask.TypeNumeric, 114: mask.TypeJSON,
    700: mask.TypeNumeric, 701: mask.TypeNumeric, 1082: mask.TypeDate, 1083: mask.TypeDate,
    1114: mask.TypeDate, 1184: mask.TypeDate, 1186: mask.TypeDate, 1266: mask.TypeDate,
    1700: mask.TypeNumeric, 2950: mask.TypeUUID, 3802: mask.TypeJSON,
}
```

`PathOverlay.MaskRow` gains a type-valid placeholder table, consulted **only** when a *confirmed*
label (`manual`/`platform`) requests redaction on a non-`TypeText` column — content detectors
(`mask.Remote`) and the flat `Overlay` layer are unaffected, since a probabilistic content-shape
guess redacting a typed column is exactly the false-positive risk the original guard exists to
prevent, and that risk doesn't go away just because this fix exists; only an explicit, confirmed,
human decision gets the new behavior:

```go
var typeValidPlaceholder = map[mask.TypeKind][]byte{
    mask.TypeDate:    []byte("0001-01-01"),          // parses under every driver's date/timestamp decoder
    mask.TypeNumeric: []byte("0"),
    mask.TypeBool:    []byte("false"),
    mask.TypeUUID:    []byte("00000000-0000-0000-0000-000000000000"),
}
```

`overrideMetrics`/`RecordMasked` continues to record only category/byte-count metadata — no new
value ever crosses into a log or metrics payload, same constraint as everything else in the masking
chain.

### Non-goals

- `TypeJSON`/structured-binary redaction — `Remote` already inspects JSON-shaped text columns today
  (`REDACTION.md`'s "a JSON blob stored in a text column" example); this fix doesn't change that
  path, only the previously-fully-skipped numeric/date/bool/uuid types.
- Partial-mask semantics for typed columns (`Profile: "partial_mask"`) — out of scope for this pass;
  `profileToken`'s existing `partial_mask -> "[masked]"` mapping only makes sense for text. A typed
  column redacted under this fix always gets `full_redact`'s type-valid placeholder regardless of
  `Profile`, until a follow-up defines what "partial" means for a date or a number.
- MySQL's own type-kind mapping is deferred to the same follow-up as Gap A's MySQL fix — this design
  covers the mapping table shape for both engines, but sequencing/PR-splitting is an implementation
  decision, not a design one.

## 3. Relationship between the two gaps

Both are instances of the same underlying issue: the wire engines resolve *some* of a column's real
schema identity (table via `tableOID`, in both engines) but not all of it (real column name; full
type-kind detail beyond "safe to redact as text or not"). Fixing Gap A (real column name) makes
Gap B's type-valid-placeholder redaction actually reach the right column when a query aliases it —
they compose, and there's no reason to ship one without eventually shipping the other, though they
can land as separate PRs (Gap A is a lower-risk, lower-effort fix; Gap B changes a public struct's
field and touches more call sites).

## 4. Testing

Both fixes need the same category of regression test `CLAUDE.md` requires for a bug fix: a test
that fails before the fix and passes after.

- **Gap A**: a `parseRowDescription`/`columnIdentity` unit test with a synthetic column-definition
  packet whose aliased name differs from its real name, asserting `Path` (not `Name`) carries the
  real name — and an integration-level `PathOverlay` test asserting a label confirmed on the real
  name still matches when the wire reports an alias.
- **Gap B**: a `PathOverlay.MaskRow` test with a `TypeDate`/`TypeNumeric` column and a confirmed
  `full_redact` label, asserting the output is the type-valid placeholder (not the raw value, and
  not skipped) — plus a test confirming `mask.Remote`/`Overlay` are unaffected (still skip non-text
  columns exactly as today) since only `PathOverlay`'s confirmed-label path changes.
