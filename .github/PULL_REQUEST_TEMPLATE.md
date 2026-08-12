## What and why

<!-- What does this change, and why? Link the issue you discussed the approach in, if any. -->

## Checklist

- [ ] Ran `make lint && make vet && go test -race ./...` locally (what CI runs)
- [ ] New masking layer or wire-protocol parser falls through on miss/error — never corrupts, never
      blocks a query unless `SKYBRIDGE_MASK_MODE=strict` is explicitly in play
- [ ] No raw PII value, token, or minted credential in a log line, error message, or metrics payload
- [ ] Bug fixes include a regression test that fails before the fix and passes after
- [ ] Updated `CONTRACT.md` if a wire/HTTP boundary's shape changed
- [ ] Updated `internal/config/config.go` doc comment + README's Configure table if a
      `SKYBRIDGE_*` env var was added/changed
- [ ] Updated `REDACTION.md` / README's "How masking works" if the masking chain's layer order or
      fallthrough behavior changed
- [ ] Updated `CLAUDE.md`'s Layout table if a role was added/moved/renamed under `cmd/skybridge`

## Testing

<!-- How did you verify this? Manual repro steps, new/updated tests, etc. -->
