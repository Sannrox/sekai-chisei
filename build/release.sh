#!/usr/bin/env bash
# Push the image produced by ./build/release-images.sh.

set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd -P)"
cd "${ROOT}"

IMAGE_TAG="${IMAGE_TAG:-sekai-chisei:local}"

if [[ -z "${DOCKER_REGISTRY:-}" ]]; then
  echo "DOCKER_REGISTRY is required (e.g. ghcr.io/sannrox/sekai-chisei)" >&2
  exit 1
fi
DOCKER_REGISTRY="$(printf '%s' "${DOCKER_REGISTRY}" | tr '[:upper:]' '[:lower:]')"

if [[ -n "${IMAGE_VERSION:-}" ]]; then
  VERSION="${IMAGE_VERSION}"
else
  VERSION="$(git describe --tags --always --dirty 2>/dev/null || echo unknown)"
  VERSION="${VERSION/+/_}"
fi
VERSION="${VERSION#v}"

REMOTE="${DOCKER_REGISTRY}:${VERSION}"
docker tag "${IMAGE_TAG}" "${REMOTE}"
echo "Push ${REMOTE}"
docker push "${REMOTE}"
