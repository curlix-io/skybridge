#!/usr/bin/env bash
# Shared multi-arch build+push helper for scripts/push-ghcr.sh and scripts/release.sh. Sourced, not
# executed directly.
#
# Supports two container engines, selected via CONTAINER_ENGINE (default: docker):
#   CONTAINER_ENGINE=docker  (default) — docker buildx build --platform ... --push, one multi-arch
#                            manifest built and pushed directly per set of tags. Requires a buildx
#                            builder with a driver that supports multi-platform output (the default
#                            "docker-container" driver does; the classic "docker" driver does not —
#                            `docker buildx create --use` once if `docker buildx ls` shows none).
#   CONTAINER_ENGINE=podman  — podman has no buildx equivalent; instead this builds one native image
#                            per platform into a local manifest list (`podman build --platform ...
#                            --manifest`), then pushes that manifest list under each requested tag
#                            (`podman manifest push --all`). Requires `podman login ghcr.io` done
#                            beforehand (podman has no `docker login`-compatible auto-detect from the
#                            docker credential helper on all platforms — log in explicitly).
#
# Either way, the point is the same: a single-arch build from an Apple Silicon Mac produces an
# arm64-only image; ECS/Fargate tasks default to linux/amd64 unless the task definition explicitly
# sets `runtimePlatform` to ARM64, so an arm64-only image fails to start there with an exec format /
# no matching manifest error that has nothing to do with the tag name or registry auth.
#
# build_and_push_image <cmd> <dockerfile> <build_tags> <platforms> <tag1> [<tag2> ...]
#   cmd         - SKYBRIDGE_CMD build-arg value (e.g. skybridge-edge)
#   dockerfile  - path to the Dockerfile to build (build-arg BUILD_TAGS is only passed when this is
#                 Dockerfile.edge, since the root Dockerfile has no such ARG)
#   build_tags  - value for Dockerfile.edge's BUILD_TAGS build-arg (may be empty)
#   platforms   - comma-separated platform list, e.g. linux/amd64,linux/arm64
#   tag*        - one or more full image:tag refs to push, e.g. ghcr.io/curlix-io/skybridge:edge-1.2.3
build_and_push_image() {
  local cmd="$1" dockerfile="$2" build_tags="$3" platforms="$4"
  shift 4
  local tags=("$@")
  local engine="${CONTAINER_ENGINE:-docker}"

  local build_arg_args=(--build-arg "SKYBRIDGE_CMD=${cmd}")
  if [ "${dockerfile}" = "Dockerfile.edge" ]; then
    build_arg_args+=(--build-arg "BUILD_TAGS=${build_tags}")
  fi

  case "${engine}" in
    docker)
      local tag_args=()
      local t
      for t in "${tags[@]}"; do
        tag_args+=(-t "${t}")
      done
      docker buildx build \
        --platform "${platforms}" \
        "${build_arg_args[@]}" \
        "${tag_args[@]}" \
        -f "${dockerfile}" \
        --push .
      ;;
    podman)
      local manifest="skybridge-build-$$-${RANDOM}"
      podman build \
        --platform "${platforms}" \
        --manifest "${manifest}" \
        "${build_arg_args[@]}" \
        -f "${dockerfile}" \
        .
      local t
      for t in "${tags[@]}"; do
        podman manifest push --all "${manifest}" "docker://${t}"
      done
      podman manifest rm "${manifest}" >/dev/null 2>&1 || true
      ;;
    *)
      echo "error: unknown CONTAINER_ENGINE '${engine}' (expected docker or podman)" >&2
      return 1
      ;;
  esac
}

require_container_engine() {
  local engine="${CONTAINER_ENGINE:-docker}"
  case "${engine}" in
    docker)
      if ! command -v docker >/dev/null 2>&1; then
        echo "error: docker not found (or set CONTAINER_ENGINE=podman to use podman instead)" >&2
        exit 1
      fi
      ;;
    podman)
      if ! command -v podman >/dev/null 2>&1; then
        echo "error: podman not found" >&2
        exit 1
      fi
      ;;
    *)
      echo "error: unknown CONTAINER_ENGINE '${engine}' (expected docker or podman)" >&2
      exit 1
      ;;
  esac
}
