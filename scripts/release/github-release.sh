#!/usr/bin/env bash
# The only script that changes a GitHub Release. Every command first refuses a
# published release, so "Re-run failed jobs" (which reuses verify-tag's
# outputs) can resume a draft but never rewrite what was published. Needs
# GH_TOKEN and GH_REPO.
#
# <kind> is how the release is marked: final, prerelease (a tag with a "-"),
# or maintenance (a tag only on its release-* line). Only final may become
# GitHub's latest release, and nothing here forces it.
#
# Usage:
#   bash scripts/release/github-release.sh guard <tag>
#       Exit 0 when the release is a draft or does not exist yet.
#   bash scripts/release/github-release.sh draft <tag> <kind> <notes> <asset>...
#       Create the draft, or resume it: drop the earlier run's assets, upload
#       these, and reset title, notes, and kind.
#   bash scripts/release/github-release.sh upload <tag> <asset>...
#       Add or replace assets on the draft.
#   bash scripts/release/github-release.sh download <tag> <dir> <asset>...
#       Download assets from the draft into <dir>.
#   bash scripts/release/github-release.sh publish <tag> <kind>
#       Publish the draft.
set -euo pipefail

fail() {
  printf 'github-release: %s\n' "$1" >&2
  exit 1
}

# Prints "draft" or "missing"; fails on a published release or a lookup error.
# A token that cannot see drafts reports a draft as not found.
release_state() {
  local tag="$1" state
  if state="$(gh release view "$tag" --json isDraft --jq .isDraft 2>&1)"; then
    [[ "$state" == true ]] || fail "release ${tag} is already published; cut a new tag instead of re-running"
    echo draft
  elif [[ "$state" == *"release not found"* ]]; then
    echo missing
  else
    fail "cannot read release ${tag}: ${state}"
  fi
}

kind_flags() {
  case "$1" in
    final) ;;
    prerelease) echo "--prerelease --latest=false" ;;
    maintenance) echo "--latest=false" ;;
    *) fail "kind must be final, prerelease, or maintenance, not $1" ;;
  esac
}

require_draft() {
  [[ "$(release_state "$1")" == draft ]] || fail "release $1 has no draft"
}

cmd="${1:-}"
[[ $# -ge 1 ]] && shift
case "$cmd" in
  guard)
    [[ $# -eq 1 ]] || fail "usage: $0 guard <tag>"
    release_state "$1" >/dev/null
    ;;
  draft)
    [[ $# -ge 4 ]] || fail "usage: $0 draft <tag> <kind> <notes> <asset>..."
    tag="$1" notes="$3"
    flags="$(kind_flags "$2")"
    read -r -a kind <<<"$flags"
    shift 3
    state="$(release_state "$tag")"
    if [[ "$state" == draft ]]; then
      # Every run rebuilds every asset; drop the earlier run's so a renamed or
      # removed asset is not published.
      names="$(gh release view "$tag" --json assets --jq '.assets[].name')"
      while IFS= read -r name; do
        [[ -n "$name" ]] && gh release delete-asset "$tag" "$name" --yes
      done <<<"$names"
      gh release upload "$tag" "$@" --clobber
      gh release edit "$tag" --title "$tag" --notes-file "$notes" --draft ${kind[@]+"${kind[@]}"}
    else
      gh release create "$tag" "$@" --draft --verify-tag ${kind[@]+"${kind[@]}"} \
        --title "$tag" --notes-file "$notes"
    fi
    ;;
  upload)
    [[ $# -ge 2 ]] || fail "usage: $0 upload <tag> <asset>..."
    tag="$1"
    shift
    require_draft "$tag"
    gh release upload "$tag" "$@" --clobber
    ;;
  download)
    [[ $# -ge 3 ]] || fail "usage: $0 download <tag> <dir> <asset>..."
    tag="$1" dir="$2"
    shift 2
    require_draft "$tag"
    for asset in "$@"; do
      gh release download "$tag" --dir "$dir" --pattern "$asset" --clobber
    done
    ;;
  publish)
    [[ $# -eq 2 ]] || fail "usage: $0 publish <tag> <kind>"
    tag="$1"
    flags="$(kind_flags "$2")"
    read -r -a kind <<<"$flags"
    require_draft "$tag"
    gh release edit "$tag" --draft=false ${kind[@]+"${kind[@]}"}
    echo "Published GitHub Release ${tag} from CHANGELOG"
    ;;
  *)
    fail "usage: $0 {guard|draft|upload|download|publish} <tag> ..."
    ;;
esac
