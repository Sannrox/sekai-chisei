#!/usr/bin/env bash

set -euo pipefail

ROOT_PATH="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd -P)"
cd "${ROOT_PATH}"

dependency_tree="$(cargo tree -p sekai-ontology --edges normal --prefix none)"
for forbidden in tonic tonic-prost tonic-health postgres reqwest axum; do
  if grep -Eq "^${forbidden} v" <<<"${dependency_tree}"; then
    echo "standalone ontology package includes forbidden dependency: ${forbidden}" >&2
    exit 1
  fi
done
