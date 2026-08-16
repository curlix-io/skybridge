# AI-Based Path Labelling — Design Doc

Status: **Draft / RFC**. This proposes how Skybridge could grow its existing path-label plumbing
(`internal/pathlabel`) into an AI-assisted classifier that proposes PII labels for table
columns / document fields, so a human only has to confirm, not discover, sensitive data. It also
proposes how the same masking chain extends from a synchronous wire-proxy into a streaming/CDC
context (Kafka, Debezium), since both point in the same direction: a labeller and a masker that no
longer assume a live, synchronous connection to the source database.

This revision makes three things concrete that the previous draft only sketched:

1. **§5** now specifies the AI classifier's model choice as a pluggable decision — an LLM-API-backed
   implementation and a self-hosted fine-tuned-NER implementation both implement the same
   `Classifier` interface, so the choice is a deployment decision, not an architectural one.
2. **§5.2** now sources samples from live wire-proxy/`dbquery` traffic already flowing through the
   agent/edge process (`internal/pathlabel/trafficsampler`), instead of a scan job dialing a second,
   dedicated read-only DSN against the source database. §4b's inline-proxy peer survey already named
   this shape — "classifies from data, schema, and ML-based analysis *as data traverses the proxy*,
   explicitly requiring no periodic scan and no separate database credential" — as the closest
   architectural match to Skybridge; this revision closes that gap rather than just noting it. The
   `SKYBRIDGE_LABELLER_DSN`-based scan job (`internal/labeller`, §5.2 in the prior revision) remains
   as an optional, secondary bootstrap path for tables/columns no live session has touched yet — see
   the tradeoff called out in §5.2 below.
3. **§7** turns the earlier "forward-looking note" into an actual proposed design for a streaming
   masking extension, reusing the existing `Masker` chain against a schema-registry-keyed identity
   instead of a live wire-protocol one.

## 1. Problem

Today, a column/field only gets a `PathOverlay` label (`internal/pathlabel/label`) if:

- a human sets it manually, or
- Presidio's content detector (`mask.Remote.Detect`, reused from the masking chain) happens to
  fire on a sampled leaf value in `internal/edge/dbquery/mask.go`'s `proposeLeaf`.

That means path-label coverage today is a side effect of live query traffic hitting Presidio's
regex/NER entity set. There is no dedicated classification pass, no use of the *column name* as a
signal, and no way to bootstrap labels for a table before anyone queries it. As schemas grow, this
leaves real gaps: a column named `dob` or `ssn_last4` with no matching Presidio entity type in the
sampled text never gets proposed, and a rarely-queried table gets no coverage at all until traffic
happens to touch it.

A second, separate problem shows up once an AI classifier is added on top of this: the most obvious
way to run a periodic classification scan is a standalone job that dials the source database itself
(§5.2 in the original draft of this doc) — which means a customer running Skybridge's egress-only
agent/edge, who has already handed the agent one credential to originate live sessions with, now has
to provision and hand over a *second*, dedicated read-only credential/DSN just so a separate scan job
can sample rows for classification. That's an extra credential to provision, rotate, and audit for a
capability the agent/edge process already has everything it needs for: it already resolves
`ObjectID`/`FieldPath` identity for every row/leaf that crosses the masking chain, and it already sees
that row's pre-mask value on the way through (`internal/edge/dbquery/mask.go`'s `proposeLeaf` call
sites, and the wire engines' own `PathOverlay` resolution points). §5.2 below removes this second
credential rather than just accepting it as a cost.

## 2. Goal

Add an AI-based labeller that proposes `label.Source == SourceProposed` labels using both column
*name* and sampled *values*, running independently of live query traffic — without touching the
redaction gate (`PathOverlay.isConfirmed`) or the propose/confirm contract already in
`internal/pathlabel/label` and `remotestore`. A steward still confirms before anything redacts live.
This is additive, not a replacement for the `Remote`/Presidio detector already wired in.

## 3. Non-goals

- Replacing Presidio's content-based masking (layer 1 of the masking chain) — that stays as-is.
- Changing `PathOverlay`'s trust model (`manual`/`platform` only redact live) — a proposal, AI-based
  or not, is always inert until confirmed.
- Running the labeller inline in the wire-proxy hot path — see §6, this is an offline job.

## 4. Landscape: how others do this

The categories below are drawn from surveying the data-classification/DLP/DSPM market and adjacent
open-source projects broadly, without tying any specific claim to a specific product name — the
point is the *pattern*, not who ships it, since exact implementation details change and specific
vendor claims can't all be independently verified from public docs alone.

### 4a. At-rest / catalog-driven discovery platforms

The dominant category: large data-classification/discovery platforms that scan connected data
sources (warehouses, object storage, managed databases) on a schedule and populate a central
catalog with sensitivity tags. Across this category:

- **Signal**: almost universally a mix of pattern/regex/dictionary matching plus some form of
  ML/NLP scoring layered on top — pure regex-only classification is treated as the baseline these
  platforms differentiate against, not the state of the art.
- **ML vs. rule-based**: genuinely mixed even within a single platform. Some products' "ML" framing
  turns out, on closer reading of their own docs, to be a deterministic scoring/threshold pass
  (hit-rate against a sample, then a specificity ranking) rather than a trained statistical model —
  worth verifying rather than assuming from marketing copy alone.
- **Confirm-before-enforce**: several products in this category do explicitly implement a
  train→predict→human-confirms→retrain loop, or an equivalent "quality score + manual
  review/adjustment" step, before a classification is trusted for policy. A few instead apply a
  continuous likelihood/confidence score with no hard human gate at all — enforcement thresholds on
  that score substitute for a review queue.
- **Batch vs. inline**: this whole category is fundamentally a scheduled/periodic scan over data at
  rest, not a query-time interceptor — classification happens independently of, and well before,
  any live access.

### 4b. Inline proxy peers (closest to Skybridge's architecture)

A smaller category of products that sit as a transparent network proxy in front of a database (or
a broader set of infrastructure) and classify/mask at query time rather than via a scheduled scan —
architecturally the closest peers to Skybridge:

- One well-documented example in this category classifies from data, schema, and ML-based analysis
  *as data traverses the proxy*, explicitly requiring **no periodic scan and no separate database
  credential** for classification — the same shape as Skybridge's masking chain running per query.
  It layers a separate rule-based policy engine for admin-defined matchers on top, and auto-classifies
  with a manual-correction UI rather than a hard confirm-before-enforce gate.
- Another example in this category is a purely inline access proxy with **no detection logic of its
  own** — it intercepts the response stream and delegates entirely to a pluggable external DLP
  provider (the same integration shape Skybridge itself uses for its own content-masking layer).
  Redaction there is automatic and immediate once enabled, with no propose/confirm workflow at all.
- A third data point: a wire-level interception product in this space was positioned around database
  *activity monitoring* rather than classification — its column-classification capability, where it
  existed, came from a separate acquirer's discovery module rather than being native to the
  interception layer itself.
- A fourth, architecturally distinct example is a data-privacy-vault product where PII fields are
  **manually schema-defined** up front rather than auto-classified at all — there's no discovery
  step for structured database columns; a separate feature does NLP-based entity detection, but only
  over unstructured text/documents, not database columns. Strongest data-exposure guarantee in the
  category (raw values never leave the vault) at the cost of re-architecting data flow around it.

### 4c. Open source / prior art

- **Presidio's structured-data mode** (an official add-on package to the Presidio project this repo
  already depends on for content masking) — the most directly relevant OSS precedent. Samples
  values per column, runs the same analyzer used for content masking, then picks one representative
  entity per column via a selection strategy: majority vote, highest confidence, or a
  confidence-threshold-then-majority-vote hybrid. No confirm workflow built in — that's left to the
  integrator, same gap this design fills for Skybridge. Presidio also ships an experimental
  LLM-augmented recognizer that does entity extraction via prompted LLM calls, additive to its
  existing regex/NER stack.
- **Open-source data catalogs' tag/classification schemas** — the best off-the-shelf *state-machine*
  reference in this space is a tag schema with exactly the shape this design wants: an
  "automated + suggested" state when a scanner proposes a tag (carrying a free-text reason field for
  provenance), flipping to "confirmed" only after a human reviews it. A sibling project in the same
  space has a similar propose/confirm tag model, but removed its own in-repo classifier in favor of
  a pluggable classifier interface/registry — i.e., this corner of the OSS ecosystem is already
  moving toward "bring your own classifier (including LLM-backed)" rather than shipping one.
- **A small, now-archived column-scanning tool** — column-name regex + NLP-on-samples, a binary
  has-PII flag, no confidence score, no confirm workflow. Useful only as a "what not to do"
  simplicity baseline — the lack of confidence scoring and a human gate is exactly the gap Skybridge
  should avoid repeating.
- **Policy-tag-consumer/tag-holder pairs** (a common two-project pattern in the Hadoop/lakehouse
  ecosystem) — one project only *consumes* classification tags for policy enforcement; a paired
  project holds the tags but has no in-repo detector of its own — both delegate classification
  upstream, the same separation-of-concerns this design keeps (labeller proposes,
  `label.Store`/`PathOverlay` enforces).
- **A lakehouse-native column-semantic-classification tool** — the closest OSS analog to
  structured-*column* (not free-text) classification found outside the catalog tools above: tags
  columns (email, phone, IP, etc.) across a metastore. Regex-rule-based, not ML/LLM — useful as
  evidence that column-level classification-as-a-scan-job is a proven shape, but not itself a source
  of a better detection *signal*.
- **Open PII-masking model/dataset projects** — a separate lineage from Presidio: fine-tuned NER
  models and their training datasets, purpose-built for PII masking rather than a rules/regex
  wrapper. Operate on free text, not columns, but are a candidate alternative or complement to
  Presidio's NER backend if Skybridge ever wants a smaller self-hosted model instead of an LLM API
  call for the content-detection layer.
- **Dead ends confirmed, not viable prior art:** a couple of once-notable enterprise data-catalog
  projects have no PII feature and are effectively in maintenance mode or have been absorbed into
  the catalog projects already covered above. A dedicated Postgres anonymization extension is
  purely manual (schema-author-declared masking rules, no detection at all) — the opposite end of
  the spectrum from a propose/confirm model. A small PII-scrubbing library is regex-only in its
  core, with NER only via opt-in companion packages, and has no confirm workflow — a masking
  library, not a labeller. An early open-source DLP scanner project's last release was over a
  decade ago. Several natural-language-to-SQL tools, data-integration/ELT tools, and LLM-guardrail
  projects either have no PII detection at all or only manual/config-driven field masking (a human
  names the field; nothing infers it) — none offer a detection signal or confirm workflow worth
  adopting, and the LLM-guardrail projects that do wrap NER/Presidio apply it to LLM prompt/response
  text, not database schema, so neither transfers directly either.

### 4d. LLM-based column classification (2024–2025 research)

This is the most directly transferable frontier signal. The task is studied academically as
"column type annotation" (CTA) — column name + sample values → semantic type label — which is
structurally identical to PII-type labelling:

- Zero/few-shot LLM prompting has been shown to reach >85% F1 on column-type-annotation benchmarks,
  matching a small fine-tuned transformer model trained on hundreds of labeled examples — evidence
  that a plain prompt-based approach is viable without any training data or model hosting.
- An open-source zero-shot LLM CTA framework exists with a documented prompt-serialization/
  label-remapping methodology, state-of-the-art on zero-shot benchmarks.
- Follow-on research layers retrieval-augmentation or few-shot context from already-labeled columns
  to stabilize output across repeated scans — directly applicable to reducing label churn across
  successive Skybridge scans of the same table.

### 4e. General data-labelling / weak-supervision prior art (beyond PII)

The propose→confirm pattern isn't PII-specific — it's a generic ML-ops problem (AI proposes, human
confirms) that the broader data-labelling ecosystem has iterated on longer than any PII-specific
tool above:

- **Weak-supervision label aggregation** — a well-known technique combines multiple noisy "labeling
  functions" (heuristics, regexes, existing models), each voting on a label; a generative label
  model estimates each function's *accuracy* without ground truth and produces one aggregated
  probabilistic label. Directly analogous to Skybridge having a column-name heuristic, a
  content-based detector, and an LLM classifier all proposing labels for the same
  `(ObjectID, FieldPath)` — this pattern argues for combining them into **one aggregated confidence
  score**, where cross-proposer *agreement* boosts confidence and *disagreement* lowers it, rather
  than three independent `label.Store.Put` calls that just merge by max-confidence today.
- **Model-assisted human-in-the-loop labelling platforms** — a model pre-fills a suggestion, a human
  accepts/corrects/rejects. Several such platforms support confidence- or disagreement-ordered
  **review queues**, auto-accepting high-confidence items and routing only low-confidence/disputed
  ones to a human — the standard shape for scaling human review beyond "review everything."
- **Active learning (uncertainty/margin sampling)** — the general technique of prioritizing which
  unlabeled items most need human review by looking at model uncertainty. Maps directly onto a
  steward review queue: order proposed labels by ascending confidence (lowest first) instead of
  FIFO/arrival order, so limited review attention concentrates where it's most likely to change the
  outcome.
- **Data-quality-expectation tooling** — expectations start as profiler-inferred suggestions that a
  human curates into a checked-in "contract." The propose→confirm lifecycle is explicit, but
  versioning is coarse (git-committed config) with no first-class confidence score — weaker than the
  ML-labelling platforms above.
- **Feature stores** — support tags/owners and, in some cases, data-quality monitoring annotations,
  but generally lack a native propose-vs-confirmed provenance field with a confidence score — the
  least mature precedent of the group.

**Implication for `label.Store`:** two upgrades beyond what the classification-platform survey
(§4a–4d) suggests on its own. First, when more than one proposer is live (content-based detection, a
column-name heuristic, and an LLM classifier), aggregate their votes into one confidence score per
`(ObjectID, FieldPath)` — agreement boosts it, disagreement lowers it — rather than relying on the
current `mergeProposed` max-confidence-wins semantics across independent `Put` calls, which treats
three proposers agreeing the same as one proposer calling `Put` three times. Second, once a review
UI exists, order the steward queue by ascending confidence (lowest first) rather than arrival order,
and consider auto-promoting labels above a high-confidence threshold to reduce steward load. Both
are phase-2 refinements (see §8) — the phase-1 design in §5 still works correctly without them, just
less efficiently at scale.

### 4f. Emerging cloud-native data-security posture management (DSPM) tools

A newer wave of cloud-native data-security posture management tools has emerged, generally doing
at-rest scanning across cloud data stores (object storage, managed databases, warehouses) combining
content sampling with contextual/ML classification, paired with a policy/risk dashboard rather than
a query-time enforcement point. None proxy live wire-protocol traffic the way Skybridge and its
inline-proxy peers (§4b) do — this category competes with the at-rest discovery platforms (§4a), not
with Skybridge's own architecture, and is relevant mainly as validation that ML/LLM-assisted
classification (vs. pure regex) is now the default market expectation for this category, not a
differentiator on its own.

### 4g. Streaming / CDC context

Standard change-data-capture and stream-processing transform mechanisms are purely static,
column-name-driven — no content inspection, no ML. Some streaming schema-registry products support
tagging schema fields for policy purposes (e.g. driving client-side field-level encryption, not
masking). General-purpose stream-processing frameworks have no built-in classification; teams
commonly wrap a content-detection service call in a custom transform themselves. The most mature
native example of inline classification+masking in a streaming pipeline found in this survey is a
managed cloud ETL service paired with a managed data-loss-prevention API, via first-party
de-identification templates mid-pipeline — but even that is a bespoke per-pipeline integration, not
a reusable masking chain. See §7 for what this implies if Skybridge extends into streaming.

### 4h. Synthesis

Three patterns recur across every category, OSS project, and general labelling system surveyed
above:

1. **Classification is decoupled from enforcement**, and a *confidence-gated propose/confirm state
   machine* (a train→predict→confirm loop, a quality score plus manual review, an
   automated-suggested→confirmed tag state, or a model-assisted review queue) is the industry-
   standard way to let an imperfect automated classifier run continuously without ever silently
   causing a false-positive redaction or false-negative miss to go live unreviewed.
2. **LLM-prompted classification over column name + samples is now a credible, low-effort signal**
   — several 2023–2025 research sources show it matching fine-tuned-model accuracy with zero
   training data, and the PII-detection ecosystem itself is adding LLM-backed recognizers as an
   *additive* option next to regex/NER, not a replacement.
3. **Multiple weak signals should be aggregated, not layered independently** — weak-supervision
   label aggregation and hit-rate-then-specificity scoring approaches both combine several noisy
   signals into one confidence number rather than trusting any single detector in isolation; active
   learning's uncertainty sampling then uses that number to prioritize scarce human review time.

Skybridge's `internal/pathlabel/label.Source` enum (`manual`/`platform`/`proposed`/`dismissed`) and
`PathOverlay`'s confirm-gate already implement pattern (1) faithfully — this design is really about
adding a second producer into an already-correct consumer contract, using pattern (2) as the signal,
with pattern (3) as a phase-2 refinement once a second proposer exists (see §4e's implication and §8).

## 5. Proposed design

**Status: implemented** at `internal/pathlabel/aiclassifier` (`Classifier`/`Scanner` interfaces,
`Scanner.ScanFields`, and the `LLM` backend from §5.1a). §5.1b (a self-hosted fine-tuned NER
backend) and §5.4 (the `Rationale` schema addition) remain future work — see §8. The classifier and
scanner are library code only; wiring a `Sampler` implementation against a real database and
running `Scanner` on a schedule is left to the caller (a cron job, a `cmd/` binary, or a control-
plane-triggered job), matching how `mask.Remote` itself is just a `Masker` the agent wires up.

### 5.1 New component: `pathlabel/aiclassifier` (or an external job)

A `Detect`-shaped interface, matching the shape already used by `mask.Remote` in
`internal/edge/dbquery/mask.go`:

```go
type Classifier interface {
    Classify(ctx context.Context, objectID, path string, samples []string) (
        category label.Category, profile string, confidence float64, ok bool)
}
```

This interface is deliberately model-agnostic — it takes the resolved `ObjectID`/`FieldPath` (the
same table/collection + field identity already resolved by the wire engines' catalog lookups, per
REDACTION.md's Path-scoped labels section) and a bounded set of sampled values (e.g. 5–20 rows,
drawn the same way `proposeLeaf` already samples today), and returns one proposed label. Two
implementations are worth building, and neither forecloses the other — see §5.1a/§5.1b. Both write
their result through the same §5.3 path (`Source: SourceProposed`, through `label.Store.Put`), so
`PathOverlay` and every downstream consumer are identical regardless of which backend produced the
proposal.

#### 5.1a Implementation A — LLM-API-backed (`aiclassifier/llm`)

Prompts an LLM (via an API call, not a self-hosted model) with:
- the resolved `ObjectID`/`FieldPath` and column/field name,
- the sampled values,
- Skybridge's existing `Category`/`Profile` taxonomy, fixed in the prompt (not open-ended, so the
  model can't invent categories `label.Category` doesn't know about),
- a requirement to return structured JSON: `{category, profile, confidence, rationale}`.

This is the CTA-research-backed approach from §4d — zero/few-shot prompting reaches >85% F1 on
column-type-annotation benchmarks with no training data, and it's the only backend of the two that
can reason about ambiguous column names using business/domain context (`acct_num` vs. `internal
tracking id` vs. `promo_code`) rather than pattern-matching sample values alone. Best suited to
columns where the *name* carries more signal than the sampled values do, and to bootstrapping
coverage on a schema Skybridge has never seen before.

`rationale` is logged for audit but never surfaces in `label.Label` (which has no free-text field
today) — worth a small schema addition (§5.4) mirroring the open-source tag-schema `reason` field
pattern noted in §4c, so a steward
reviewing a proposed label in a UI has more to go on than a bare confidence number.

#### 5.1b Implementation B — self-hosted fine-tuned NER

Runs a fine-tuned token-classification model (e.g. a DistilBERT/T5 model trained on one of the open
PII-masking model/dataset projects referenced in §4c, or an equivalent locally-hosted model) over
each sampled *value*, the same way `mask.Remote`'s Presidio backend already does — but as a
dedicated small model rather than an LLM API call. This is not a new detection *pattern*; it's a
different backend for the same `Classifier` interface, distinguished from Implementation A by:

- **No outbound API dependency** — the model runs in-process or as a local sidecar, which matters
  for deployments that can't or won't send column samples to a third-party LLM API even inside a
  classification job (some Skybridge operators may accept sending samples to their own LLM
  provider but not want a dependency on ours). This directly serves Skybridge's "clone it, `go
  build`, run against your own database, zero required SaaS dependency" positioning
  (`CLAUDE.md`'s framing) better than an LLM-API-only design would.
- **Lower marginal cost at high scan volume** — no per-token API billing once the model is hosted;
  matters more as scan frequency/table count grows (see §5.5's cost controls either way).
- **Weaker on column-name-driven ambiguity** — it classifies sample *values*, not the column name's
  business meaning, so it's a strictly narrower signal than Implementation A for schema-only
  columns with few or no non-null sampled values.

Both implementations share the same interface, sampling code, and output path — the choice is a
per-deployment configuration decision (which backend `aiclassifier` is built/configured against),
not a fork in the design. A deployment could reasonably run both and let per-`(ObjectID,FieldPath)`
confidence (or, later, the §4e aggregation step) decide which proposal wins when they disagree.

### 5.2 Where it runs: off the wire-proxy hot path, but fed by live traffic, not a second DSN

**Status: implemented** at `internal/pathlabel/trafficsampler` (`Buffer`, `Run`). The classifier
itself still never runs inline per query — an LLM call is higher-latency and higher-cost than a
Presidio regex/NER call, and putting it on the query hot path would violate the "masking never
blocks a live database session" principle (`CLAUDE.md`'s code-review checklist). What changed from
the original draft is *where the samples it classifies come from*.

The original draft proposed a **separate, periodic job dialing its own read-only DSN** to sample
rows (the shape `internal/labeller` + `sqlsampler`/`mongosampler` still implement, kept below as a
secondary path). That works, but it requires provisioning a second database credential purely for
classification, on top of the one the agent/edge process already holds to originate live sessions.
§4b's inline-proxy peer survey already flagged the alternative: a classifier that reads samples "as
data traverses the proxy," requiring "no periodic scan and no separate database credential." Since
the agent/edge process already resolves `ObjectID`/`FieldPath` for every row/leaf that reaches the
masking chain and already sees its pre-mask value, that value is sitting right there for free — no
new connection needed.

`trafficsampler.Buffer` is a bounded, in-process, LRU-evicted cache of recently-observed values per
`(ObjectID, FieldPath)`. It's fed by `Buffer.Observe`, called from every call site that already
resolves identity for `PathOverlay`/`proposeLeaf`:

- `internal/edge/dbquery/mask.go`'s `maskRows`/`maskDocuments`, via a new `Options.SampleCollector`
  field (`internal/edge/dbquery/executor.go`) — every free-text leaf's pre-mask value is observed
  regardless of whether `mask.Remote`'s content Detector fires, since the AI classifier needs
  samples of ordinary values too, not just Presidio-flagged ones.
- The transparent wire-proxy engines' own `PathOverlay` resolution points — `internal/wire/postgres`
  (`Engine.WithSampleCollector`, called from `maskDataRow`), `internal/wire/mysql`
  (`Engine.WithSampleCollector`, threaded onto `state` and called from `maskTextRow`), and
  `internal/wire/mongo` (`Engine.WithSampleCollector`, threaded onto `bsonMasker` and called from
  `maskString`) — so the same traffic-fed sampling covers the transparent wire proxy, not just
  `dbquery`'s one-shot exec path. All three are a no-op (nil collector) unless wired at engine
  construction, exactly like `WithOrgID`/`WithCatalogResolver` already are.
- `internal/agent`'s `engineFactory` (`internal/agent/clienttls.go`) threads one shared
  `trafficsampler.Buffer` into every engine it builds, via `buildTrafficSampler`/
  `startTrafficSampler` (`internal/agent/agent.go`), wired into both `RunListener` and `RunTunnel` —
  and, since `config.Edge.WireProxy` is a `config.Agent` loaded the same way
  (`cmd/skybridge/edge.go`), the `edge` role's co-hosted wire proxy gets this for free with no
  separate wiring.

`trafficsampler.Run` is a periodic loop — same shape as `internal/labeller.Run`'s ticker, minus the
DSN: each cycle calls `Buffer.Fields()` (every `(ObjectID, FieldPath)` currently holding at least one
buffered sample) and classifies them via the same `aiclassifier.Scanner` used by the DSN-based job,
writing through the same `label.Store.Put` path as `SourceProposed`. It runs as a background
goroutine inside the same agent/edge process already holding the live session — not a separate
role/binary, and not a separate credential. It's enabled by config alone
(`SKYBRIDGE_TRAFFIC_SAMPLER_LLM_ENDPOINT` + `SKYBRIDGE_PATH_LABEL_URL` — see the README's Configure
table and `internal/config/config.go`'s `Agent` struct) — no code change needed to turn it on for a
given deployment. `buildTrafficSampler` deliberately reuses the same `remotestore.Store` instance
`buildMaskerWithOverlay` already builds for `PathOverlay` when `SKYBRIDGE_PATH_LABEL_URL` is set,
rather than opening a second store, so this classifier's proposals and `PathOverlay`'s confirmed-label
reads share one sync loop.

**Discovery tradeoff, stated plainly.** Traffic-fed discovery means coverage tracks what's actually
queried: a hot table gets classified quickly, a table nobody has touched gets nothing, ever — this is
strictly worse than a DSN-based `information_schema`/`ListCollectionNames` crawl for *cold-start*
coverage of tables no one queries. §5's own design already accepted this same tradeoff at the
sampling layer for the pre-existing traffic-driven `proposeLeaf` proposer (§1); this section just
extends it to the LLM classifier's sampling too, in exchange for removing the second credential. The
mitigation is additive, not a replacement: an operator who wants day-one coverage for a rarely-queried
table can still run `internal/labeller` against the same optional read-only DSN it always supported
(`SKYBRIDGE_LABELLER_DSN`) — now framed as an opt-in bootstrap/cold-start pass rather than the primary
mechanism. A deployment with no such DSN configured simply accepts that coverage follows traffic,
which for most PII-bearing tables (the ones actually being queried in production) is not a meaningful
gap in practice.

Rationale for keeping classification itself off the hot path, unchanged from the original draft:

- LLM calls are higher-latency and higher-cost than a Presidio regex/NER call; putting them on the
  query hot path would violate the "masking never blocks a live database session" principle
  (`CLAUDE.md`'s code-review checklist) unless carefully bounded — safer to keep them off it
  entirely. `Observe` itself is a cheap, non-blocking, in-memory map write; only the periodic
  `Run` loop's `Classify` calls are the expensive part, and those already run off-path.
- This mirrors nearly every platform surveyed in §4a for the *classification* step — they are almost
  universally scheduled/batch scanners, not inline classifiers — while matching §4b's closest peer
  for the *sampling* step, which is the distinction this revision draws out.

### 5.3 Output: always `SourceProposed`, through the existing merge path

The classifier calls `label.Store.Put` with `Source: SourceProposed` — never `manual`/`platform` —
so `PathOverlay.isConfirmed` continues to gate redaction exactly as it does today; zero change to
the masking chain or its fallthrough contract. Repeated scans accumulate through the existing
`mergeProposed` semantics (confidence takes the max, `SampleCount` sums), which already gives a
natural self-consistency signal across scans without new merge logic — directly analogous to the
self-consistency/retrieval techniques the LLM-CTA literature uses to stabilize output.

If this runs as a separate service (rather than agent-side), it should push through the same
`POST .../pii-path-labels/propose` endpoint `remotestore.Store` already batches to — no new
control-plane contract needed, per `CLAUDE.md`'s "follow the existing pull/push shape" guidance.

### 5.4 Schema addition (optional, phase 2)

Add an optional `Rationale string` field to `label.Label`, populated only by non-human sources, so
a steward UI can show *why* a label was proposed (mirrors the open-source tag-schema pattern from
§4c). This is additive
to the `Label` struct and does not change `Lookup`/`Put`/`ListBySource` behavior for existing
callers that ignore it.

### 5.5 Safety / cost controls

- Never send raw row values anywhere they'd be logged or retained beyond the classification
  call itself — same rule as `internal/mask/metrics` (counts/categories only, never values) applies
  doubly hard here since full row samples, not single values, are the input.
- Bound sample count and scan frequency per `ObjectID`; make both configurable with a floor, same
  shape as every other `SKYBRIDGE_*` pull/push integration (`internal/agent/overlay_source.go`
  pattern cited in `CLAUDE.md`).
- `SKYBRIDGE_MASK_MODE`-style best-effort semantics: a classifier failure (LLM API error, timeout,
  or a self-hosted model unavailable) must never block the scan job's next `ObjectID`, and must
  never touch existing confirmed labels.
- Backend choice (§5.1a vs §5.1b) is a single config switch (e.g. `SKYBRIDGE_AICLASSIFIER_BACKEND=
  llm|local-ner`), following the same shape as every other pluggable-backend config in this repo —
  it should not require different call sites or a different output schema.

## 6. What does *not* change

- `mask.Masker` interface and chain fallthrough contract — untouched.
- `PathOverlay`'s confirm gate (`manual`/`platform` only) — untouched.
- `mask.Remote`/Presidio's role as the live content-masking layer — untouched; the AI classifier is
  a second, independent *proposal* producer, not a masking layer itself.

## 7. Streaming / CDC masking — proposed design

### 7.1 Why this is harder than the wire proxy

Skybridge's synchronous wire-proxy model resolves `ObjectID`/`FieldPath` identity live and
authoritatively from the database itself (catalog lookup, column-definition packets,
request/response correlation) — classification and masking happen together, in order, exactly
once, before any byte leaves. A streaming/CDC extension (Kafka, Debezium, Flink) does not have this
luxury:

- No vendor/OSS project surveyed in §4 offers ML/LLM-based masking as a standard streaming
  primitive today — Debezium and Kafka Connect SMTs are static, name-driven only (`MaskField`,
  `column.mask.with.N.chars`); GCP Dataflow + Cloud DLP is the most mature native example of inline
  classification+masking in a streaming pipeline, and even that is a bespoke per-pipeline
  integration, not a reusable masking chain.
- The harder architectural change isn't the `Masker` interface itself — a Kafka/Debezium consumer
  could run the same `Remote`/`PathOverlay`/`Overlay` chain per message, one message at a time, the
  same way the wire proxy runs it per row. It's **identity resolution**: streaming identity has to
  come from a schema-registry lookup (Avro/Protobuf schema ID) instead of a live wire-protocol
  handshake, and has to tolerate schema evolution and at-least-once/replayed delivery — a label
  pulled at time T may not match the schema version a replayed message was produced under, a
  consistency problem the synchronous proxy model simply has no equivalent of today.

### 7.2 Proposed shape: a new `Masker` caller, not a new masking chain

Reuse `internal/mask`'s existing `Masker` interface and chain (`Remote`, `PathOverlay`, `Overlay`)
unchanged — the fallthrough contract ("a miss falls through unmasked, never corrupted") is exactly
as valid for a Kafka message as it is for a Postgres row. What's new is a **Kafka Connect SMT (or a
Kafka Streams/Flink transform) that plays the role the wire engines play today**: resolve
`(ObjectID, FieldPath)` for each field in a message, build a `mask.Column`/row equivalent, and call
`chain.MaskRow` before the message is produced to its destination topic. Concretely:

- **Identity resolution** — `ObjectID` becomes `"{org}:kafka:{topic}"` (or, for Debezium CDC topics,
  the same `"{org}:{driver}:{database}:{table}"` shape `dbquery` already uses, recovered from the
  Debezium envelope's `source` block) instead of a wire-protocol catalog lookup. `FieldPath` comes
  from walking the decoded Avro/Protobuf/JSON payload with the same `docpath.Walk` already used for
  nested Mongo documents — no new path-resolution code needed, just a new caller of it.
  A schema registry (the common Kafka ecosystem pattern for this) supplies the schema, by schema ID
  embedded in the message, replacing the live-connection schema Postgres/MySQL/Mongo supply on the
  wire.
- **Label lookup** — unchanged: `PathOverlay` looks up `(ObjectID, FieldPath)` in `label.Store`
  exactly as it does today. This is precisely where the AI classifier in §5 pays off twice: a
  schema-registry-keyed `ObjectID` is exactly the identity shape a periodic classification scan
  already needs to cover tables/topics that aren't being actively queried, so §5's classifier is a
  **precondition** for this section, not separate work — build it once, use it for both the proxy
  and the streaming path.
- **Schema evolution** — a label lookup miss on a newly-added field must fall through to `Overlay`
  or unmasked exactly like an unresolved `ObjectID` does in the wire proxy today (§REDACTION.md's
  "never an error" rule for Postgres/Mongo) — never block or fail the message. A steward confirming
  a label for a new field only takes effect for messages produced *after* the label is confirmed,
  the same latency the wire proxy already has between a `remotestore` poll and a confirmed label
  taking effect (`SKYBRIDGE_PATH_LABEL_URL`/`_POLL_SECONDS`).
- **Replay** — since Kafka/CDC topics are replayable and labels can change over time, a replayed
  message masked under today's labels may differ from how it would have been masked when first
  produced. This is a real, new consistency gap the synchronous proxy doesn't have (§7.1) — the
  design choice is to accept it (mask with whatever labels are current at processing time, same
  best-effort philosophy as `SKYBRIDGE_MASK_MODE=best-effort`) rather than try to version every
  label change against every possible replay window, which no surveyed vendor attempts either.

### 7.3 Non-goals for this phase

- A general-purpose Flink/Spark UDF library — start with a single Kafka Connect SMT
  (`skybridge-mask-smt`) covering the Debezium CDC case, since that's the most direct analog to "a
  table Skybridge already knows how to identify." Whether this lives in-repo (behind a build tag,
  `querystudio`-style) or as a separate module depending on `internal/mask`/`internal/pathlabel` as
  a library is open — see §8, item 8.
- Solving replay-consistency versioning (§7.2) — accept best-effort masking against current labels,
  revisit only if a specific compliance requirement demands otherwise.

## 8. Open questions

1. Which model/hosting: call an existing LLM API directly from the classifier job vs. routing
   through the control plane (keeps the agent/edge binaries free of a new outbound dependency,
   consistent with `querystudio`'s build-tag isolation pattern for optional add-ons)?
2. Confidence threshold for auto-surfacing a proposal to a steward's review queue vs. silently
   accumulating sample count until a threshold is crossed (a three-tier confidence-band model vs. a
   five-tier likelihood-band model, per §4a, are both plausible references).
3. Should `Rationale` (§5.4) be part of this phase or deferred — depends on whether a review UI
   exists yet to display it.
4. Once the LLM classifier ships alongside the existing Presidio-based `proposeLeaf`/heuristic
   proposers, should `label.Store` gain a weak-supervision-style aggregation step (§4e) that combines
   concurrent proposals into one confidence score, or is per-proposer `mergeProposed` (current
   max-confidence-wins behavior) good enough until real disagreement between proposers is observed
   in practice? Leaning toward deferring — premature to build aggregation for a disagreement
   pattern that hasn't been seen yet.
5. Once a steward review UI exists, order its queue by ascending confidence (§4e's active-learning
   point) rather than arrival order — a UI-layer decision, not a `label.Store` schema change, so it
   can land independently of this doc's phase 1.
6. Should implementation A (LLM API) or B (self-hosted fine-tuned NER, §5.1b) ship first, or
   both at once behind the same config switch? Leaning toward A first — it's the higher-signal
   backend for the coverage gap in §1 (ambiguous column names), and B can follow once there's a
   concrete no-outbound-dependency requirement from a specific deployment, rather than building it
   speculatively.
7. Which streaming system to target first for §7 — a Kafka Connect SMT (broadest reuse across any
   Kafka-based CDC pipeline, including but not limited to Debezium) vs. a Debezium-specific
   transform (narrower, but can lean harder on the CDC envelope's `source` block for identity). No
   strong evidence either way yet; likely resolved by whichever a design partner actually runs.
8. Does §7's SMT belong in this repository at all, or as a separate module/repo that depends on
   `internal/mask`/`internal/pathlabel` as a library? `CLAUDE.md`'s stdlib-only-core constraint
   (`internal/wire`, `internal/mask`, `internal/tunnel`, `internal/gateway`) would be broken by a
   Kafka client dependency if pulled into this module directly — favors a separate repo/module over
   a new build tag, unlike `querystudio`'s in-repo pattern.
9. **Resolved**: table discovery for the DSN-based `internal/labeller` job started as an explicit
   `SKYBRIDGE_LABELLER_TABLES` list (the simpler first cut this doc originally described) but now
   defaults to a live `information_schema.tables` / `ListCollectionNames` crawl
   (`sqlsampler.ListTables`, `mongosampler.ListTables`) when that list is unset, so a newly-created
   table/collection doesn't need an operator to notice and add it. This reopened a scale question the
   original explicit-list design never had to answer: a schema with tens of thousands of tables would
   otherwise fan out into a proportional number of LLM `Classify` calls every cycle.
   `internal/labeller`'s `scheduler` bounds this — `MaxObjectsPerScan` caps how many tables one cycle
   actually samples, `RescanIntervalSeconds` skips a table scanned too recently, and
   least-recently-scanned tables are preferred each cycle so a large schema still gets covered
   incrementally across many cycles instead of needing one cycle to cover it all. The traffic-fed
   path added in §5.2 sidesteps this scale question entirely for the primary path — `Buffer.Fields()`
   is bounded by `Buffer`'s own `maxFields` LRU cap, not a schema-size-proportional crawl — since
   discovery there is "whatever traffic has touched," never a full-schema enumeration.
10. **Resolved**: `trafficsampler.Buffer.Observe` is now wired into all four masking call sites —
    `internal/edge/dbquery/mask.go` (one-shot `db_query_*`/Studio-dispatch exec path) and all three
    transparent wire-proxy engines (`internal/wire/postgres`, `internal/wire/mysql`,
    `internal/wire/mongo`) — via each package's own `WithSampleCollector` builder, mirroring the
    existing `WithOrgID`/`WithCatalogResolver` pattern. The enabling config landed as a new
    `config.Agent` sub-block (`TrafficSamplerLLMEndpoint`/`_LLMAPIKey`/`_LLMCategories`/
    `_LLMMinConfidence`/`_MaxFields`/`_MaxSamplesPerField`/`_ScanIntervalSeconds`, all
    `SKYBRIDGE_TRAFFIC_SAMPLER_*`), not a new top-level role — `internal/agent.RunListener`/
    `RunTunnel` build one shared `trafficsampler.Buffer` per agent process and thread it into every
    engine via `engineFactory`, and start `trafficsampler.Run` alongside the other background sync
    loops. Since `config.Edge.WireProxy` is a `config.Agent`, the `edge` role's co-hosted wire proxy
    inherits this with no separate wiring. Remaining open question: `internal/labeller`'s DSN-based
    scan job and this traffic-fed path currently run as fully independent config/code paths with no
    shared state (both can propose to the same `label.Store`, but neither knows about the other) —
    fine for now since `mergeProposed`'s max-confidence-wins semantics already handle two proposers
    disagreeing, but worth revisiting if a deployment runs both and wants them coordinated rather than
    just both landing in the same store.
