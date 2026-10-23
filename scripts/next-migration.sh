#!/usr/bin/env bash
# Print the next free PostgreSQL migration file number and registry index
# against the main branch, so a migration added on a branch can be
# renumbered in one step after another lands first.
set -euo pipefail

ROOT_PATH="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd -P)"
cd "${ROOT_PATH}"

git fetch --quiet origin main
last="$(git ls-tree --name-only origin/main src/db/postgres/ \
  | sed -n 's#^src/db/postgres/\([0-9]\{4\}\)_.*#\1#p' | sort | tail -1)"
next=$((10#${last} + 1))
printf 'file: src/db/postgres/%04d_<name>.sql\n' "${next}"
printf 'registry: mig(%d, "<name>", ..) in src/db/postgres.rs\n' "$((next - 1))"
