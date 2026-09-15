#!/usr/bin/env bash
# Compile linux binaries in the pinned rust image, then wrap them.
# The image tag is git describe, never a separate "local" name.

set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd -P)"
cd "${ROOT}"

CHANNEL="$(sed -n 's/^channel = "\(.*\)"/\1/p' rust-toolchain.toml)"
RUST_IMAGE="${RUST_IMAGE:-rust:${CHANNEL}-bookworm@sha256:9a73a5088750b4c95158ab26629c854c3d6fc4b173cb7bc8079ad252d8ed7bfa}"
if [[ "${RUST_IMAGE}" != *"${CHANNEL}"* ]]; then
  echo "RUST_IMAGE=${RUST_IMAGE} does not match rust-toolchain.toml channel ${CHANNEL}" >&2
  exit 1
fi

if ! git rev-parse --is-inside-work-tree >/dev/null 2>&1; then
  echo "release-images.sh requires a git checkout" >&2
  exit 1
fi
if [[ -n "$(git status --porcelain)" ]]; then
  echo "Working tree is dirty. Commit or stash before building images." >&2
  git status --porcelain >&2
  exit 1
fi

GIT_COMMIT="$(git rev-parse HEAD)"
GIT_VERSION="$(git describe --tags --always --abbrev=14 HEAD)"
GIT_VERSION="${GIT_VERSION/+/_}"
if [[ -z "${GIT_VERSION}" || "${GIT_VERSION}" == *dirty* ]]; then
  echo "Refusing to build a dirty image tag: ${GIT_VERSION:-<empty>}" >&2
  exit 1
fi
IMAGE_NAME="${IMAGE_NAME:-sekai-chisei}"
IMAGE_TAG="${IMAGE_NAME}:${GIT_VERSION}"

mkdir -p _output/cargo-target _output/linux-bins

docker run --rm \
  --volume "${ROOT}:/src:ro" \
  --volume "${ROOT}/_output/cargo-target:/target" \
  --volume "${ROOT}/_output/linux-bins:/out" \
  --workdir /src \
  --env CARGO_TARGET_DIR=/target \
  --env CARGO_HOME=/target/cargo-home \
  --env SEKAI_GIT_COMMIT="${GIT_COMMIT}" \
  --env SEKAI_GIT_VERSION="${GIT_VERSION}" \
  "${RUST_IMAGE}" \
  bash -c 'cargo build --release --locked --workspace --bins &&
    cp /target/release/sekai-chisei /target/release/chisei-gateway /target/release/sekaictl /out/'

docker build \
  -f build/server-image/Dockerfile \
  --build-arg VCS_REF="${GIT_COMMIT}" \
  -t "${IMAGE_TAG}" \
  _output/linux-bins

printf '%s\n' "${IMAGE_TAG}" > _output/image-tag
printf 'GIT_VERSION=%s\n' "${GIT_VERSION}" > _output/compose.env
echo "Built ${IMAGE_TAG}"
