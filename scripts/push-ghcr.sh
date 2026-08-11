#!/usr/bin/env bash
# Manual/ad hoc build+push of the skybridge image to ghcr.io/curlix-io/skybridge, for pushing
# outside of a tagged release (see .github/workflows/ghcr-publish.yml for the tag-driven path).
#
# One binary (./cmd/skybridge), one image — the role (agent/gateway/edge/labeller) is picked by the
# container's runtime args (e.g. `docker run ghcr.io/curlix-io/skybridge:1.2.3 edge`), not by which
# image tag was pulled. Pushes:
#   ghcr.io/curlix-io/skybridge:<version>   (+ :latest)
#
# Requires login to ghcr.io done beforehand (this script does not log in for you) — for docker, a
# GitHub PAT with write:packages, or `gh auth token | docker login ghcr.io -u <user>
# --password-stdin`; for podman, `podman login ghcr.io` (see scripts/lib/container-build.sh for how
# each engine is driven — CONTAINER_ENGINE=docker (default) uses buildx, CONTAINER_ENGINE=podman
# uses a local manifest list). Also requires multi-platform build support: for docker, a buildx
# builder whose driver supports it (the default "docker-container" driver does; the classic "docker"
# driver does not — `docker buildx create --use` once if `docker buildx ls` doesn't already show
# one); podman's qemu-based emulation for foreign platforms usually needs `qemu-user-static`/
# binfmt registered on Linux hosts (Docker Desktop's podman machine has this built in on macOS).
#
# Builds+pushes a single multi-arch (linux/amd64 + linux/arm64) manifest per tag, rather than a
# plain single-platform build (which only builds for the host's own architecture). A plain build run
# from an Apple Silicon Mac produces an arm64-only image; ECS/Fargate tasks default to linux/amd64
# unless the task definition explicitly sets `runtimePlatform` to ARM64, so an arm64-only image
# fails to start there with an exec format / no matching manifest error that has nothing to do with
# the tag name or registry auth.
#
# Usage:
#   VERSION=1.2.3 ./scripts/push-ghcr.sh
#   ./scripts/push-ghcr.sh 1.2.3
#   CONTAINER_ENGINE=podman VERSION=1.2.3 ./scripts/push-ghcr.sh
set -euo pipefail

cd "$(dirname "${BASH_SOURCE[0]}")/.."
source scripts/lib/container-build.sh

VERSION="${1:-${VERSION:-}}"
if [ -z "$VERSION" ]; then
  echo "usage: VERSION=<version> $0   OR   $0 <version>" >&2
  exit 1
fi

require_container_engine

IMAGE="ghcr.io/curlix-io/skybridge"
PLATFORMS="linux/amd64,linux/arm64"
TAGS=("${IMAGE}:${VERSION}" "${IMAGE}:latest")

echo "==> building+pushing ${IMAGE}:${VERSION} (engine=${CONTAINER_ENGINE:-docker}, ${PLATFORMS})"
build_and_push_image "${PLATFORMS}" "${TAGS[@]}"
