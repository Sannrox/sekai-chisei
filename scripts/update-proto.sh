#!/usr/bin/env bash

set -euo pipefail

ROOT_PATH="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd -P)"
cd "${ROOT_PATH}"

for name in sekai.proto chisei.proto; do
  if ! cmp -s "proto/${name}" "crates/sekai-proto/proto/${name}"; then
    cp "proto/${name}" "crates/sekai-proto/proto/${name}"
    echo "Updated crates/sekai-proto/proto/${name}"
  fi
done
