#!/usr/bin/env bash
# Manual/ad hoc build+push of the skybridge images to ghcr.io/curlix-io/skybridge, for pushing
# outside of a tagged release (see .github/workflows/ghcr-publish.yml for the tag-driven path).
#
# Builds agent/gateway from the root Dockerfile's SKYBRIDGE_CMD build arg, and edge from
# Dockerfile.edge (bundles the AWS CLI edge's aws_readonly_cli tool shells out to — the root
# Dockerfile's distroless base has no shell/package manager to add that with). Pushes each as its
# own tag prefix:
#   ghcr.io/curlix-io/skybridge:agent-<version>   (+ :agent-latest)
#   ghcr.io/curlix-io/skybridge:gateway-<version> (+ :gateway-latest)
#   ghcr.io/curlix-io/skybridge:edge-<version>    (+ :edge-latest)
#
# Requires: docker login ghcr.io (a GitHub PAT with write:packages, or `gh auth token | docker
# login ghcr.io -u <user> --password-stdin`) done beforehand — this script does not log in for you.
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

CMDS=(skybridge-agent skybridge-gateway skybridge-edge)
PREFIXES=(agent gateway edge)
DOCKERFILES=(Dockerfile Dockerfile Dockerfile.edge)

for i in "${!CMDS[@]}"; do
  cmd="${CMDS[$i]}"
  prefix="${PREFIXES[$i]}"
  dockerfile="${DOCKERFILES[$i]}"
  echo "==> building ${cmd} -> ${IMAGE}:${prefix}-${VERSION} (${dockerfile})"
  docker build \
    --build-arg "SKYBRIDGE_CMD=${cmd}" \
    -t "${IMAGE}:${prefix}-${VERSION}" \
    -t "${IMAGE}:${prefix}-latest" \
    -f "${dockerfile}" .
  echo "==> pushing ${IMAGE}:${prefix}-${VERSION}"
  docker push "${IMAGE}:${prefix}-${VERSION}"
  docker push "${IMAGE}:${prefix}-latest"
done
