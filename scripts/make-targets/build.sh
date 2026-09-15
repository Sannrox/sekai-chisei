#!/usr/bin/env bash

set -euo pipefail

ROOT_PATH="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd -P)"
cd "${ROOT_PATH}"

if [ $# -eq 0 ]; then
  cargo build --release --locked --workspace --bins
else
  cargo build --release --locked --bin "$1"
fi
