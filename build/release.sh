#!/usr/bin/env bash
# Push the image produced by ./build/release-images.sh.
# Same git-describe tag; DOCKER_REGISTRY is only the push destination.

set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd -P)"
cd "${ROOT}"

if [[ -z "${DOCKER_REGISTRY:-}" ]]; then
  echo "DOCKER_REGISTRY is required (e.g. ghcr.io/sannrox/sekai-chisei)" >&2
  exit 1
fi
DOCKER_REGISTRY="$(printf '%s' "${DOCKER_REGISTRY}" | tr '[:upper:]' '[:lower:]')"

if [[ -n "${IMAGE_TAG:-}" ]]; then
  LOCAL_TAG="${IMAGE_TAG}"
elif [[ -f _output/image-tag ]]; then
  LOCAL_TAG="$(cat _output/image-tag)"
else
  echo "Run ./build/release-images.sh first (missing _output/image-tag)" >&2
  exit 1
fi

VERSION="${LOCAL_TAG##*:}"
REMOTE="${DOCKER_REGISTRY}:${VERSION}"
docker tag "${LOCAL_TAG}" "${REMOTE}"
echo "Push ${REMOTE}"
docker push "${REMOTE}"
