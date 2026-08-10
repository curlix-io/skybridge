# aiclassifier demo: with vs. without the AI classifier

Two containers (`stub-llm`, `runner`) run the real `internal/pathlabel/aiclassifier` code
(`Scanner`/`LLM`) against 5 fabricated columns and print a side-by-side of what gets proposed with
today's baseline (content-only detection, gated on live query traffic) vs. with the AI classifier
(column name + samples, independent of traffic). See `docs/AI_PATH_LABELLING_DESIGN.md` for the
full design.

```sh
cd examples/aiclassifier-demo
docker compose up --build --abort-on-container-exit
docker compose down
```

## Flow

```
                                   ┌───────────────────────────┐
                                   │   Fabricated columns       │
                                   │   (stand-in for a real DB) │
                                   │                             │
                                   │  users.email      queried   │
                                   │  users.ssn_last4  queried   │
                                   │  users.dob        queried   │
                                   │  archive_users.email  ─ ─ ─ ┼─ never queried
                                   │  users.display_name queried │
                                   └──────────────┬──────────────┘
                                                  │
                        ┌─────────────────────────┴─────────────────────────┐
                        │                                                   │
                        ▼                                                   ▼
        ┌───────────────────────────────┐                 ┌───────────────────────────────────┐
        │   WITHOUT the AI classifier   │                 │      WITH the AI classifier        │
        │   (today's baseline)          │                 │   internal/pathlabel/aiclassifier   │
        │                                │                 │                                     │
        │  Only runs on fields that      │                 │  Runs on every field regardless of  │
        │  live query traffic actually   │                 │  query traffic — a periodic scan,   │
        │  touches (proposeLeaf, gated   │                 │  not a side effect of traffic       │
        │  on Queried==true)             │                 │  (docs §5.2)                        │
        │             │                  │                 │             │                       │
        │             ▼                  │                 │             ▼                       │
        │  mask.Remote-style content     │                 │  Scanner.ScanFields                 │
        │  regex/NER on the VALUE only   │                 │    │                                 │
        │  — never the column name       │                 │    ▼                                 │
        │  (EMAIL_ADDRESS, US_SSN, ...)  │                 │  Sampler.Sample(objectID, path)     │
        │             │                  │                 │    │ (name + N sample values)        │
        │             ▼                  │                 │    ▼                                 │
        │  Hit → propose                 │                 │  Classifier.Classify                │
        │  Miss → nothing, forever,      │                 │    (LLM prompted with name+samples, │
        │  until traffic changes         │                 │     constrained to fixed taxonomy)  │
        └───────────────┬────────────────┘                 └──────────────┬──────────────────────┘
                        │                                                   │
                        ▼                                                   ▼
              1/5 fields covered                                  4/5 fields covered
              (only users.email —                                  (adds ssn_last4, dob via
               content happened to                                  column name; adds
               look email-shaped)                                   archive_users.email despite
                                                                      zero query traffic)
                        │                                                   │
                        └─────────────────────┬─────────────────────────────┘
                                              ▼
                          Both paths write ONLY label.Source == SourceProposed
                                              │
                                              ▼
                          ┌───────────────────────────────────────┐
                          │      label.Store (PathOverlay)        │
                          │                                        │
                          │  proposed → inert, never redacts       │
                          │  live traffic on its own                │
                          │                                        │
                          │  steward reviews → promotes to          │
                          │  manual/platform → NOW it redacts       │
                          └───────────────────────────────────────┘
```

## Why the gap exists

- **Column-name signal**: `ssn_last4` (a bare 4-digit value) and `dob` (a plain date string) have
  no PII *shape* a content-only regex/NER detector matches — `mask.Remote`'s default entity set
  never fires on them. The AI classifier sees the *column name* too, which is often the only real
  signal for these.
- **Traffic independence**: `archive_users.email` is genuinely sensitive, but nobody has queried
  that table — `proposeLeaf`-style detection is a side effect of live traffic, so it never gets a
  chance to run at all. The AI classifier runs a scheduled scan over known objects regardless of
  traffic (`docs/AI_PATH_LABELLING_DESIGN.md` §5.2), so coverage doesn't depend on someone
  querying the table first.
- **Both agree on negatives**: `users.display_name` correctly gets no proposal either way — the
  AI classifier isn't looser, just broader in what signal it can use.

## Safety property (unchanged either way)

Every proposal, from either path, is `label.Source == SourceProposed` — inert until a steward
promotes it. `PathOverlay`'s confirm gate (only `manual`/`platform` labels redact) is untouched by
this demo or by the real `aiclassifier` package.
