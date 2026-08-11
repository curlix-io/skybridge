#!/usr/bin/env bash
# Cuts a new release entirely locally — no dependency on GitHub Actions:
#   1. creates+pushes a vX.Y.Z git tag
#   2. creates the GitHub release for that tag via `gh release create`
#   3. builds+pushes the three skybridge docker images to ghcr.io/curlix-io/skybridge (multi-arch,
#      via buildx), same layout as scripts/push-ghcr.sh:
#        ghcr.io/curlix-io/skybridge:agent-<version>   (+ :agent-latest)
#        ghcr.io/curlix-io/skybridge:gateway-<version> (+ :gateway-latest)
#        ghcr.io/curlix-io/skybridge:edge-<version>    (+ :edge-latest, + bare :latest)
#
# This does NOT run .github/workflows/release.yml or ghcr-publish.yml — if those are enabled on
# this repo they'll also fire on the tag push and do the same work again; disable/ignore them or
# use this script instead of relying on them. For an ad hoc image push with no tag/release at all,
# use scripts/push-ghcr.sh instead.
#
# Requires:
#   - gh CLI authenticated (`gh auth login`), push access to origin
#   - docker login ghcr.io done beforehand (a GitHub PAT with write:packages, or
#     `gh auth token | docker login ghcr.io -u <user> --password-stdin`)
#   - a docker buildx builder that supports multi-platform output (`docker buildx create --use`
#     once if `docker buildx ls` doesn't already show one)
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

echo "==> pushing ${TAG} to origin"
git push origin "$TAG"

echo "==> creating GitHub release ${TAG} on ${REPO}"
gh release create "$TAG" \
  --repo "$REPO" \
  --title "$TAG" \
  --generate-notes

IMAGE="ghcr.io/curlix-io/skybridge"
PLATFORMS="linux/amd64,linux/arm64"

CMDS=(skybridge-agent skybridge-gateway skybridge-edge)
PREFIXES=(agent gateway edge)
DOCKERFILES=(Dockerfile Dockerfile Dockerfile.edge)

for i in "${!CMDS[@]}"; do
  cmd="${CMDS[$i]}"
  prefix="${PREFIXES[$i]}"
  dockerfile="${DOCKERFILES[$i]}"
  tag_args=(-t "${IMAGE}:${prefix}-${VERSION}" -t "${IMAGE}:${prefix}-latest")
  # skybridge-edge is the single-install binary most customers use (see CLAUDE.md), so it also
  # gets the bare :latest alias on top of its edge-latest tag.
  if [ "${prefix}" = "edge" ]; then
    tag_args+=(-t "${IMAGE}:latest")
  fi
  echo "==> building+pushing ${cmd} -> ${IMAGE}:${prefix}-${VERSION} (${dockerfile}, ${PLATFORMS})"
  docker buildx build \
    --platform "${PLATFORMS}" \
    --build-arg "SKYBRIDGE_CMD=${cmd}" \
    "${tag_args[@]}" \
    -f "${dockerfile}" \
    --push .
done

echo "==> done."
echo "    GitHub release: https://github.com/${REPO}/releases/tag/${TAG}"
echo "    GHCR images:    https://github.com/curlix-io/skybridge/pkgs/container/skybridge (agent-${VERSION}, gateway-${VERSION}, edge-${VERSION}, latest)"
