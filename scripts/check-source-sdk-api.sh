#!/usr/bin/env bash
# Fail when sekai-source-sdk public-api.txt disagrees with the crate version.
set -euo pipefail
root="$(cd "$(dirname "$0")/.." && pwd)"
cd "$root"
cargo test -p sekai-source-sdk --locked --test public_api -- --nocapture
