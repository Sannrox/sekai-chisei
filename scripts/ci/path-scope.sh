#!/usr/bin/env bash
# Whether a pull-request path filter matches. A failed git diff reports a
# match so an optional lane runs instead of being skipped (#2807).
#
# Usage: bash scripts/ci/path-scope.sh <output-key> <path-regex>
# Reads GITHUB_EVENT_NAME, BASE, and GITHUB_OUTPUT.
set -euo pipefail

[ "$#" -eq 2 ] || {
  echo "usage: path-scope.sh <output-key> <path-regex>" >&2
  exit 2
}
key="$1"
pattern="$2"
[ -n "${GITHUB_OUTPUT:-}" ] || {
  echo "GITHUB_OUTPUT is required" >&2
  exit 2
}

write() {
  echo "$key=$1" >>"$GITHUB_OUTPUT"
}

if [ "${GITHUB_EVENT_NAME:-}" != "pull_request" ]; then
  write true
  exit 0
fi

if ! files="$(git diff --name-only "$BASE"...HEAD)"; then
  write true
  exit 0
fi
if grep -Eq "$pattern" <<<"$files"; then
  write true
else
  write false
fi
