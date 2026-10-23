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

# The compatibility matrix pins the proto digest; keep it in step.
cargo run --quiet --locked --bin sekaictl -- admin compatibility generate --out compatibility.json
