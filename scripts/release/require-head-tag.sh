#!/usr/bin/env bash
# The current commit must carry <tag>. git describe --exact-match can pick
# another tag on the same commit (#2810).
#
# Usage: bash scripts/release/require-head-tag.sh <tag>
set -euo pipefail

fail() {
  printf 'require-head-tag: %s\n' "$1" >&2
  exit 1
}

[[ $# -eq 1 ]] || fail "usage: $0 <tag>"
tag="$1"
[[ -n "$tag" ]] || fail "tag is empty"
git tag --points-at HEAD | grep -Fxq -- "$tag" || fail "HEAD does not carry tag ${tag}"
