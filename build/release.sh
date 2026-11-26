#!/usr/bin/env bash
# Push the server and gateway images produced by ./build/release-images.sh.
# Same tag as release-images.sh (RELEASE_TAG or git describe); DOCKER_REGISTRY is only the push destination.
# The gateway image is ${DOCKER_REGISTRY}/chisei-gateway.

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
  VERSION="${RELEASE_TAG:-$(git describe --tags --always --abbrev=14 HEAD)}"
  VERSION="${VERSION/+/_}"
  docker buildx imagetools create \
    -t "${DOCKER_REGISTRY}:${VERSION}" \
    "${DOCKER_REGISTRY}:${VERSION}-amd64" \
    "${DOCKER_REGISTRY}:${VERSION}-arm64"
  echo "Published ${DOCKER_REGISTRY}:${VERSION}"
  GATEWAY_REGISTRY="$(printf '%s' "${DOCKER_REGISTRY}/chisei-gateway" | tr '[:upper:]' '[:lower:]')"
  docker buildx imagetools create \
    -t "${GATEWAY_REGISTRY}:${VERSION}" \
    "${GATEWAY_REGISTRY}:${VERSION}-amd64" \
    "${GATEWAY_REGISTRY}:${VERSION}-arm64"
  echo "Published ${GATEWAY_REGISTRY}:${VERSION}"
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

if [[ -n "${GATEWAY_IMAGE_TAG:-}" ]]; then
  GATEWAY_LOCAL_TAG="${GATEWAY_IMAGE_TAG}"
elif [[ -f _output/gateway-image-tag ]]; then
  GATEWAY_LOCAL_TAG="$(cat _output/gateway-image-tag)"
else
  echo "Run ./build/release-images.sh first (missing _output/gateway-image-tag)" >&2
  exit 1
fi

VERSION="${LOCAL_TAG##*:}"
if [[ "${VERSION}" == *dirty* ]]; then
  echo "Refusing to push a dirty image tag: ${LOCAL_TAG}" >&2
  exit 1
fi
GATEWAY_VERSION="${GATEWAY_LOCAL_TAG##*:}"
if [[ "${GATEWAY_VERSION}" != "${VERSION}" ]]; then
  echo "Gateway image tag ${GATEWAY_LOCAL_TAG} does not match server tag ${LOCAL_TAG}" >&2
  exit 1
fi

ARCH="$(docker version -f '{{.Server.Arch}}')"
REMOTE="${DOCKER_REGISTRY}:${VERSION}-${ARCH}"
docker tag "${LOCAL_TAG}" "${REMOTE}"
echo "Push ${REMOTE}"
docker push "${REMOTE}"

GATEWAY_REGISTRY="$(printf '%s' "${DOCKER_REGISTRY}/chisei-gateway" | tr '[:upper:]' '[:lower:]')"
GATEWAY_REMOTE="${GATEWAY_REGISTRY}:${VERSION}-${ARCH}"
docker tag "${GATEWAY_LOCAL_TAG}" "${GATEWAY_REMOTE}"
echo "Push ${GATEWAY_REMOTE}"
docker push "${GATEWAY_REMOTE}"
