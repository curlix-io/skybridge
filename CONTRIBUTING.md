# Contributing to Skybridge

Thanks for considering a contribution. Skybridge is a standalone, independently open-sourced Go
module — see [CLAUDE.md](./CLAUDE.md) for the full architecture rundown before diving in.

## Before you start

- For anything beyond a small fix, open an issue first to discuss the approach. It saves everyone
  a wasted PR.
- Check existing issues and PRs so you're not duplicating in-flight work.

## Development setup

```sh
go build ./...        # needs only Go >= 1.26; stdlib-only core, no external services required
make build             # builds bin/skybridge (all roles: agent/gateway/edge/labeller)
make test              # go test ./...
make race              # go test -race ./...
make vet               # go vet ./...
make fmt               # go fmt ./...
make lint              # gofmt -l . (what CI runs)
```

No editable installs, no service containers required to build or run the unit test suite. The
`deploy/docker-compose.yml` stack (Presidio analyzer/anonymizer + the agent) is only needed to
exercise the `Remote` content-detection masking layer end to end — see the
[README's Quick start](./README.md#quick-start).

**Before opening a PR**, run exactly what CI runs:

```sh
make lint && make vet && go test -race ./...
```

## Code guidelines

- The wire-proxy core (`internal/wire`, `internal/mask`, `internal/tunnel`, `internal/gateway`) is
  **stdlib-only by design** — don't introduce a third-party dependency there. The single binary's
  other roles (aws-sdk-go-v2, gRPC, k8s client libs) already have looser constraints, but a new
  dependency anywhere still needs justification in the PR description.
- **Fallthrough, never corrupt.** Every masking layer and every wire-protocol parser must leave an
  unhandled value exactly as it was rather than guess, drop, or partially transform it. This is a
  hard invariant — see [CLAUDE.md's Security model](./CLAUDE.md#security-model).
- Never log a raw masked/unmasked value, a session token, or a minted database credential.
- Bug fixes need a regression test that fails before the fix and passes after.
- Test names follow `Test<Subject>_<Condition>` (e.g. `TestRemoteMasker_MaskRow`).
- Keep new tests hermetic (in-process TLS listener, `httptest.Server`, etc.) rather than reaching
  for Docker — a handful of packages already do this (`internal/edge/transport`, `internal/wiremtls`,
  `internal/gateway`).

## Docs stay in sync

If your change touches a wire/HTTP contract, an `SKYBRIDGE_*` env var, the masking chain's layer
order, or a role's wiring in `cmd/skybridge`, update the corresponding doc in the same PR:

| Change | Update |
|---|---|
| Tunnel frame format, control message, or either HTTP contract body | `CONTRACT.md` |
| New/changed `SKYBRIDGE_*` env var | `internal/config/config.go` doc comment + README's Configure table |
| Masking chain layer order, fallthrough behavior, or what's live vs. groundwork | `REDACTION.md` + README's "How masking works" section |
| A role added/moved/renamed under `cmd/skybridge` | `CLAUDE.md`'s Layout table + relevant workflow/goreleaser config |

## Commit messages / PRs

- Keep the PR title short and focused on the "why", not just the "what".
- Squash noisy WIP commits before requesting review where practical.
- Link the issue you discussed the approach in, if there was one.

## Reporting bugs

Open a GitHub issue with reproduction steps, expected vs. actual behavior, and your Skybridge
version/role/config (`SKYBRIDGE_DB_TYPE`, role, relevant env vars — redact secrets).

## Reporting security issues

Do **not** open a public issue for a security vulnerability. See [SECURITY.md](./SECURITY.md).

## License

By contributing, you agree that your contributions will be licensed under the
[Apache-2.0 license](./LICENSE) that covers this project.
