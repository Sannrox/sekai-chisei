#!/usr/bin/env bash
# Generate a connector from the template, build it, and run its conformance
# tests against this checkout's SDK. Starts from the workspace lockfile (cargo
# only prunes it for the new root) and reuses the target directory, so
# dependencies keep their pinned versions and are not rebuilt.
set -euo pipefail
root="$(cd "$(dirname "$0")/.." && pwd)"
cd "$root"
out="$(mktemp -d)"
trap 'rm -rf "$out"' EXIT
cargo run --locked --quiet --bin sekaictl -- admin connectors new demo-connector \
  --out "$out/demo-connector" --sdk-path "$root"
cp Cargo.lock "$out/demo-connector/"
CARGO_TARGET_DIR="$root/target" cargo test \
  --manifest-path "$out/demo-connector/Cargo.toml"
