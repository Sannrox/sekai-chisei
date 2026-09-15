#!/usr/bin/env bash

set -euo pipefail

ROOT_PATH="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd -P)"
cd "${ROOT_PATH}"

cargo check --workspace --all-targets --locked
cargo clippy --workspace --all-targets --locked -- -D warnings
