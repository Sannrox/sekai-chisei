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

if [[ "${RELEASE_MANIFEST:-}" == 1 ]]; then
  if [[ -n "$(git status --porcelain)" ]]; then
    echo "Working tree is dirty. Commit or stash before publishing the image manifest." >&2
    exit 1
  fi
  VERSION="$(git describe --tags --always --abbrev=14 HEAD)"
  VERSION="${VERSION/+/_}"
  docker buildx imagetools create \
    -t "${DOCKER_REGISTRY}:${VERSION}" \
    "${DOCKER_REGISTRY}:${VERSION}-amd64" \
    "${DOCKER_REGISTRY}:${VERSION}-arm64"
  echo "Published ${DOCKER_REGISTRY}:${VERSION}"
  exit 0
fi

if [[ -n "${IMAGE_TAG:-}" ]]; then
  LOCAL_TAG="${IMAGE_TAG}"
elif [[ -f _output/image-tag ]]; then
  LOCAL_TAG="$(cat _output/image-tag)"
else
  echo "Run ./build/release-images.sh first (missing _output/image-tag)" >&2
  exit 1
fi

VERSION="${LOCAL_TAG##*:}"
if [[ "${VERSION}" == *dirty* ]]; then
  echo "Refusing to push a dirty image tag: ${LOCAL_TAG}" >&2
  exit 1
fi

ARCH="$(docker version -f '{{.Server.Arch}}')"
REMOTE="${DOCKER_REGISTRY}:${VERSION}-${ARCH}"
docker tag "${LOCAL_TAG}" "${REMOTE}"
echo "Push ${REMOTE}"
docker push "${REMOTE}"
