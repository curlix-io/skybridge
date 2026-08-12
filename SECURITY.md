# Security Policy

Skybridge sits in front of a live database and masks PII before it leaves your network — security
issues here have direct impact. Please report vulnerabilities privately rather than through a public
GitHub issue.

## Reporting a vulnerability

Use GitHub's private reporting flow: open the
[Security tab](https://github.com/curlix-io/skybridge/security) on this repository and click
**"Report a vulnerability"** to open a private security advisory. This reaches maintainers directly
without disclosing details publicly.

Please include:

- Skybridge version/commit and role(s) involved (`agent`/`gateway`/`edge`/`labeller`)
- Relevant configuration (`SKYBRIDGE_DB_TYPE`, deployment shape — listener/tunnel/edge — and any
  masking layers enabled; redact tokens/credentials)
- Reproduction steps and expected vs. actual behavior
- Impact assessment if known (e.g. "unmasked PII reaches the client", "credential logged in
  cleartext", "policy bypass in edge tool dispatch")

## What counts as a security issue here

Given the [security model](./CLAUDE.md#security-model), the following are treated as
vulnerabilities rather than ordinary bugs:

- A masking layer silently drops/corrupts data instead of falling through unmasked, or a masker miss
  results in a value being *dropped* rather than passed through as-is
- Raw PII, a session token, or a minted database credential appearing in a log line, error message,
  or metrics payload
- A wire-protocol parser misinterpreting bytes in a way that could expose unmasked PII
- A policy bypass in `internal/edge/policy.go` or `internal/edge/k8sexec/policy.go` (e.g. a blocked
  kubectl verb or non-allowlisted AWS call executing anyway)
- Anything that lets a client obtain a credential the database would accept directly when
  `SKYBRIDGE_INJECT_CREDENTIALS=true` is set

## Response

We aim to acknowledge new reports within a few business days and will work with you on a fix and
coordinated disclosure timeline before any public write-up.

## Supported versions

Security fixes are made against the `main` branch and included in the next tagged release. There is
no long-term-support branch at this time.
