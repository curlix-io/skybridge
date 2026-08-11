#!/usr/bin/env bash
# Manual/ad hoc build+push of the skybridge images to ghcr.io/curlix-io/skybridge, for pushing
# outside of a tagged release (see .github/workflows/ghcr-publish.yml for the tag-driven path).
#
# Builds agent/gateway from the root Dockerfile's SKYBRIDGE_CMD build arg, and edge from
# Dockerfile.edge (bundles the AWS CLI edge's aws_readonly_cli tool shells out to — the root
# Dockerfile's distroless base has no shell/package manager to add that with). Also builds a second
# edge image with Dockerfile.edge's BUILD_TAGS=querystudio, matching `make edge-querystudio` — the
# plain edge image never has Query Studio dispatch compiled in (see CLAUDE.md's "default build has
# zero optional-integration code" contract), so anyone needing Query Studio must deploy the
# edge-querystudio tag instead, not assume it's already in edge-<version>. Pushes each as its own
# tag prefix:
#   ghcr.io/curlix-io/skybridge:agent-<version>              (+ :agent-latest)
#   ghcr.io/curlix-io/skybridge:gateway-<version>            (+ :gateway-latest)
#   ghcr.io/curlix-io/skybridge:edge-<version>               (+ :edge-latest, + bare :latest)
#   ghcr.io/curlix-io/skybridge:edge-querystudio-<version>   (+ :edge-querystudio-latest)
#
# Requires: docker login ghcr.io (a GitHub PAT with write:packages, or `gh auth token | docker
# login ghcr.io -u <user> --password-stdin`) done beforehand — this script does not log in for you.
# Also requires a docker buildx builder that supports multi-platform output (the default
# "docker-container" driver does; the classic "docker" driver does not) — `docker buildx create --use`
# once if `docker buildx ls` doesn't already show one.
#
# Builds+pushes a single multi-arch (linux/amd64 + linux/arm64) manifest per tag via buildx, rather
# than a plain `docker build` (which only builds for the host's own architecture). A plain build run
# from an Apple Silicon Mac produces an arm64-only image; ECS/Fargate tasks default to linux/amd64
# unless the task definition explicitly sets `runtimePlatform` to ARM64, so an arm64-only image
# fails to start there with an exec format / no matching manifest error that has nothing to do with
# the tag name or registry auth.
#
# Usage:
#   VERSION=1.2.3 ./scripts/push-ghcr.sh
#   ./scripts/push-ghcr.sh 1.2.3
set -euo pipefail

cd "$(dirname "${BASH_SOURCE[0]}")/.."

VERSION="${1:-${VERSION:-}}"
if [ -z "$VERSION" ]; then
  echo "usage: VERSION=<version> $0   OR   $0 <version>" >&2
  exit 1
fi

IMAGE="ghcr.io/curlix-io/skybridge"
PLATFORMS="linux/amd64,linux/arm64"

CMDS=(skybridge-agent skybridge-gateway skybridge-edge skybridge-edge)
PREFIXES=(agent gateway edge edge-querystudio)
DOCKERFILES=(Dockerfile Dockerfile Dockerfile.edge Dockerfile.edge)
BUILD_TAGS=("" "" "" "querystudio")

for i in "${!CMDS[@]}"; do
  cmd="${CMDS[$i]}"
  prefix="${PREFIXES[$i]}"
  dockerfile="${DOCKERFILES[$i]}"
  build_tags="${BUILD_TAGS[$i]}"
  tag_args=(-t "${IMAGE}:${prefix}-${VERSION}" -t "${IMAGE}:${prefix}-latest")
  # skybridge-edge is the single-install binary most customers use (see CLAUDE.md), so it also
  # gets the bare :latest alias on top of its edge-latest tag.
  if [ "${prefix}" = "edge" ]; then
    tag_args+=(-t "${IMAGE}:latest")
  fi
  build_arg_args=(--build-arg "SKYBRIDGE_CMD=${cmd}")
  # Only Dockerfile.edge declares BUILD_TAGS; the root Dockerfile has no such ARG, so passing it
  # there would just be an unused-build-arg warning for no benefit.
  if [ "${dockerfile}" = "Dockerfile.edge" ]; then
    build_arg_args+=(--build-arg "BUILD_TAGS=${build_tags}")
  fi
  echo "==> building+pushing ${cmd} -> ${IMAGE}:${prefix}-${VERSION} (${dockerfile}, tags=[${build_tags}], ${PLATFORMS})"
  docker buildx build \
    --platform "${PLATFORMS}" \
    "${build_arg_args[@]}" \
    "${tag_args[@]}" \
    -f "${dockerfile}" \
    --push .
done
