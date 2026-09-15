#!/usr/bin/env bash
# Compile linux binaries in the pinned rust image, then wrap them.
# Host `cargo build --release` remains the developer build.

set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd -P)"
cd "${ROOT}"

CHANNEL="$(sed -n 's/^channel = "\(.*\)"/\1/p' rust-toolchain.toml)"
RUST_IMAGE="${RUST_IMAGE:-rust:${CHANNEL}-bookworm@sha256:9a73a5088750b4c95158ab26629c854c3d6fc4b173cb7bc8079ad252d8ed7bfa}"
if [[ "${RUST_IMAGE}" != *"${CHANNEL}"* ]]; then
  echo "RUST_IMAGE=${RUST_IMAGE} does not match rust-toolchain.toml channel ${CHANNEL}" >&2
  exit 1
fi
GIT_COMMIT="$(git rev-parse HEAD 2>/dev/null || echo unknown)"
GIT_VERSION="$(git describe --tags --always --dirty 2>/dev/null || echo unknown)"

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
  bash -lc 'cargo build --release --locked --workspace --bins &&
    cp /target/release/sekai-chisei /target/release/chisei-gateway /target/release/sekaictl /out/'

IMAGE_TAG="${IMAGE_TAG:-sekai-chisei:local}"

docker build \
  -f build/server-image/Dockerfile \
  --build-arg VCS_REF="${GIT_COMMIT}" \
  -t "${IMAGE_TAG}" \
  _output/linux-bins

if [[ "${IMAGE_TAG}" != "sekai-chisei:local" ]]; then
  docker tag "${IMAGE_TAG}" sekai-chisei:local
fi
