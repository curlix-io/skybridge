#!/usr/bin/env bash
# Cuts a new tagged release: creates+pushes a vX.Y.Z tag, which is the single trigger that fans out
# to the two tag-driven GitHub Actions workflows already in this repo:
#   .github/workflows/release.yml      goreleaser -> GitHub release + binary archives (+ brew tap)
#   .github/workflows/ghcr-publish.yml docker build+push -> ghcr.io/curlix-io/skybridge (agent/
#                                       gateway/edge tags, multi-arch)
# This script does not build or push anything itself (no local docker/goreleaser dependency) — it
# only creates the tag and waits for/reports on the two workflow runs so a normal cut doesn't require
# tailing the Actions UI by hand. For an untagged, ad hoc image push, use scripts/push-ghcr.sh instead.
#
# Requires: gh CLI authenticated (`gh auth status`), push access to origin.
#
# Usage:
#   VERSION=1.2.3 ./scripts/release.sh
#   ./scripts/release.sh 1.2.3
#   ./scripts/release.sh v1.2.3
set -euo pipefail

cd "$(dirname "${BASH_SOURCE[0]}")/.."

RAW_VERSION="${1:-${VERSION:-}}"
if [ -z "$RAW_VERSION" ]; then
  echo "usage: VERSION=<version> $0   OR   $0 <version>" >&2
  exit 1
fi

# Normalize to a bare vX.Y.Z tag name.
VERSION="${RAW_VERSION#v}"
TAG="v${VERSION}"

if ! [[ "$VERSION" =~ ^[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
  echo "error: version must be semver X.Y.Z (got '${RAW_VERSION}')" >&2
  exit 1
fi

if ! command -v gh >/dev/null 2>&1; then
  echo "error: gh CLI not found — install it (https://cli.github.com) and run 'gh auth login'" >&2
  exit 1
fi
gh auth status >/dev/null

if [ -n "$(git status --porcelain)" ]; then
  echo "error: working tree is not clean — commit or stash changes before releasing" >&2
  exit 1
fi

if git rev-parse "$TAG" >/dev/null 2>&1; then
  echo "error: tag ${TAG} already exists locally" >&2
  exit 1
fi

REMOTE_URL="$(git remote get-url origin)"
REPO="${REMOTE_URL#*github.com[:/]}"
REPO="${REPO%.git}"

echo "==> tagging ${TAG} on $(git rev-parse --short HEAD)"
git tag -a "$TAG" -m "Release ${TAG}"

echo "==> pushing ${TAG} to origin (triggers release.yml + ghcr-publish.yml on ${REPO})"
git push origin "$TAG"

echo "==> waiting for GitHub Actions to pick up the tag..."
sleep 8

for workflow in release.yml ghcr-publish.yml; do
  echo "==> ${workflow} run for ${TAG}:"
  run_id="$(gh run list --repo "$REPO" --workflow "$workflow" --event push --limit 5 \
    --json databaseId,headBranch,status,conclusion \
    --jq "[.[] | select(.headBranch == \"${TAG}\")][0].databaseId" || true)"
  if [ -z "${run_id:-}" ] || [ "$run_id" = "null" ]; then
    echo "    no run found yet — check: gh run list --repo ${REPO} --workflow ${workflow}"
    continue
  fi
  echo "    run ${run_id} — streaming status (ctrl-c to stop watching, the release continues)"
  gh run watch "$run_id" --repo "$REPO" --exit-status || \
    echo "    ${workflow} run ${run_id} did not succeed — check: gh run view ${run_id} --repo ${REPO} --log-failed"
done

echo "==> done. GitHub release: https://github.com/${REPO}/releases/tag/${TAG}"
echo "==> GHCR images: https://github.com/curlix-io/skybridge/pkgs/container/skybridge (agent-${VERSION}, gateway-${VERSION}, edge-${VERSION}, latest)"
