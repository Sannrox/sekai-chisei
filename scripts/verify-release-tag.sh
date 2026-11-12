#!/usr/bin/env bash
# Refuse a v* tag that is lightweight, unsigned, signed by an unknown key,
# or whose version does not equal the workspace version; and refuse a tag
# whose commit is on neither main nor the tag's maintenance line.
#
# Usage:
#   bash scripts/verify-release-tag.sh verify <tag> [commit-sha]
#   bash scripts/verify-release-tag.sh line <tag>
#   bash scripts/verify-release-tag.sh ancestry <tag> <commit-sha>
#   bash scripts/verify-release-tag.sh self-test
#
# `ancestry` reads `${RELEASE_REF_PREFIX}main` and `${RELEASE_REF_PREFIX}<line>`
# (default prefix `refs/remotes/origin/`); fetch both before calling it.
set -euo pipefail
trap '' PIPE

SCRIPT_PATH="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)/$(basename -- "${BASH_SOURCE[0]}")"
ROOT_PATH="${RELEASE_ROOT:-$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)}"
FINGERPRINTS_FILE="${RELEASE_TAG_FINGERPRINTS:-$ROOT_PATH/security/release-tag-fingerprints}"
KEY_FILE="${RELEASE_TAG_KEY:-$ROOT_PATH/security/release-tag-key.asc}"
REF_PREFIX="${RELEASE_REF_PREFIX:-refs/remotes/origin/}"
TAG_RE='^v([0-9]+)\.([0-9]+)\.[0-9]+(-(rc|beta)\.[0-9]+)?$'

fail() {
  printf 'verify-release-tag: %s\n' "$1" >&2
  exit 1
}

normalize_fpr() {
  printf '%s' "$1" | tr '[:lower:]' '[:upper:]' | tr -d '[:space:]'
}

load_allowed_fingerprints() {
  local line
  ALLOWED_FPRS=()
  [[ -f "$FINGERPRINTS_FILE" ]] || fail "missing fingerprints file: ${FINGERPRINTS_FILE}"
  while IFS= read -r line || [[ -n "$line" ]]; do
    [[ "$line" =~ ^[[:space:]]*# ]] && continue
    [[ -z "${line// }" ]] && continue
    ALLOWED_FPRS+=("$(normalize_fpr "$line")")
  done <"$FINGERPRINTS_FILE"
  [[ ${#ALLOWED_FPRS[@]} -gt 0 ]] || fail "no fingerprints in ${FINGERPRINTS_FILE}"
}

fingerprint_allowed() {
  local got="$1" allowed
  for allowed in "${ALLOWED_FPRS[@]}"; do
    [[ "$got" == "$allowed" ]] && return 0
  done
  return 1
}

workspace_version() {
  python3 -c 'import re,sys; from pathlib import Path; text=Path(sys.argv[1]).read_text(); m=re.search(r"(?ms)^\[package\][^\[]*?^version\s*=\s*\"([^\"]+)\"", text); sys.exit("Cargo.toml has no [package] version") if not m else print(m.group(1))' "$ROOT_PATH/Cargo.toml"
}

import_allowed_key() {
  [[ -f "$KEY_FILE" ]] || fail "missing release-tag public key: ${KEY_FILE}"
  gpg --batch --import "$KEY_FILE" >/dev/null 2>&1 || fail "could not import ${KEY_FILE}"
}

verify_release_tag() {
  local tag="$1" expected_commit="${2:-}" objtype peeled raw status_fpr primary_fpr
  [[ "$tag" =~ $TAG_RE ]] || fail "invalid release tag: ${tag}"
  load_allowed_fingerprints
  import_allowed_key

  objtype="$(git cat-file -t "refs/tags/${tag}" 2>/dev/null)" || fail "tag ${tag} was not found"
  [[ "$objtype" == "tag" ]] || fail "tag ${tag} is lightweight; release tags must be annotated"

  if [[ -n "$expected_commit" ]]; then
    [[ "$expected_commit" =~ ^[0-9a-f]{40}$ ]] || fail "expected commit must be a full lowercase SHA"
    peeled="$(git rev-parse "${tag}^{commit}")"
    [[ "$peeled" == "$expected_commit" ]] || fail "tag ${tag} resolves to ${peeled}, expected ${expected_commit}"
  fi

  raw="$(git verify-tag --raw "$tag" 2>&1)" || true
  [[ "$raw" == *VALIDSIG* ]] || fail "tag ${tag} is unsigned or the signature is not valid"
  status_fpr="$(awk '/^\[GNUPG:\] VALIDSIG / { print $3; exit }' <<<"$raw")"
  primary_fpr="$(awk '/^\[GNUPG:\] VALIDSIG / { print $12; exit }' <<<"$raw")"
  status_fpr="$(normalize_fpr "$status_fpr")"
  primary_fpr="$(normalize_fpr "$primary_fpr")"
  fingerprint_allowed "$status_fpr" || fingerprint_allowed "$primary_fpr" || fail "tag ${tag} is signed by an unknown key"

  local version="${tag#v}" expected
  expected="$(workspace_version)"
  [[ "$version" == "$expected" ]] || fail "tag ${tag} does not match workspace version ${expected}"
  printf 'Release tag %s is annotated, signed, and matches workspace version %s\n' "$tag" "$expected"
}

# Prints the maintenance line a tag releases from: one per minor,
# `release-<major>.<minor>`.
release_line() {
  local tag="$1"
  [[ "$tag" =~ $TAG_RE ]] || fail "invalid release tag: ${tag}"
  printf 'release-%s.%s\n' "${BASH_REMATCH[1]}" "${BASH_REMATCH[2]}"
}

# A tag releases from main, or from its own maintenance line only.
verify_ancestry() {
  local tag="$1" commit="$2" line ref
  line="$(release_line "$tag")"
  for ref in "${REF_PREFIX}main" "${REF_PREFIX}${line}"; do
    if git rev-parse -q --verify "${ref}^{commit}" >/dev/null &&
      git merge-base --is-ancestor "$commit" "$ref"; then
      printf 'Release tag %s commit %s is on %s\n' "$tag" "$commit" "${ref#"$REF_PREFIX"}"
      return 0
    fi
  done
  fail "tag ${tag} commit ${commit} is on neither main nor ${line}"
}

expect_failure() {
  local message="$1" output
  shift
  if output="$(bash "$SCRIPT_PATH" verify "$@" 2>&1)"; then
    fail "expected verification failure containing: ${message}"
  fi
  [[ "$output" == *"$message"* ]] || fail "verification failed without expected message: ${message}"
}

# The ancestry cases need no signing; they use local branches as the refs.
ancestry_self_test() {
  local work="$1" base on_main on_line on_other_line on_feature
  [[ "$(release_line v2.0.1)" == release-2.0 ]] || fail "v2.0.1 must map to release-2.0"
  [[ "$(release_line v2.1.0-rc.1)" == release-2.1 ]] || fail "v2.1.0-rc.1 must map to release-2.1"
  [[ "$(release_line v0.1.5)" == release-0.1 ]] || fail "v0.1.5 must map to release-0.1"

  git -C "$work" checkout -q -B main
  base="$(git -C "$work" rev-parse HEAD)"
  git -C "$work" commit -q --allow-empty -m on-main
  on_main="$(git -C "$work" rev-parse HEAD)"
  git -C "$work" checkout -q -b release-2.0 "$base"
  git -C "$work" commit -q --allow-empty -m on-line
  on_line="$(git -C "$work" rev-parse HEAD)"
  git -C "$work" checkout -q -b release-2.1 "$base"
  git -C "$work" commit -q --allow-empty -m on-other-line
  on_other_line="$(git -C "$work" rev-parse HEAD)"
  git -C "$work" checkout -q -b feature "$base"
  git -C "$work" commit -q --allow-empty -m on-feature
  on_feature="$(git -C "$work" rev-parse HEAD)"

  local run=(env RELEASE_REF_PREFIX=refs/heads/ bash "$SCRIPT_PATH" ancestry)
  (cd "$work" && "${run[@]}" v2.0.1 "$on_main" >/dev/null) || fail "a main commit must pass"
  (cd "$work" && "${run[@]}" v2.0.1 "$on_line" >/dev/null) || fail "a release-2.0 commit must pass for v2.0.1"
  local commit output
  for commit in "$on_other_line" "$on_feature"; do
    if output="$(cd "$work" && "${run[@]}" v2.0.1 "$commit" 2>&1)"; then
      fail "commit ${commit} off main and release-2.0 must be refused"
    fi
    [[ "$output" == *"on neither main nor release-2.0"* ]] || fail "unexpected refusal: ${output}"
  done
  if (cd "$work" && "${run[@]}" v2.1.1 "$on_line" >/dev/null 2>&1); then
    fail "a release-2.0 commit must not release v2.1.1"
  fi
}

self_test() {
  local tmp work gnupg fpr cargo_toml
  # gpg-agent sockets fail on long macOS TMPDIR paths; keep this under /tmp.
  tmp="$(mktemp -d /tmp/sc-rel-tag.XXXXXX)"
  work="${tmp}/work"
  gnupg="${tmp}/gpg"
  mkdir -m 700 "$gnupg"
  export GNUPGHOME="$gnupg"
  printf 'pinentry-mode loopback\n' >"${gnupg}/gpg.conf"
  printf 'allow-loopback-pinentry\n' >"${gnupg}/gpg-agent.conf"
  gpg --batch --pinentry-mode loopback --passphrase '' \
    --quick-generate-key "Release self-test <release-self-test@example.invalid>" ed25519 default never >/dev/null 2>&1
  fpr="$(gpg --batch --list-secret-keys --with-colons | awk -F: '/^fpr:/{print $10; exit}')"
  [[ -n "$fpr" ]] || fail "could not generate a self-test signing key"
  gpg --batch --armor --export "$fpr" >"${tmp}/key.asc"
  printf '%s\n' "$fpr" >"${tmp}/fingerprints"
  export RELEASE_TAG_KEY="${tmp}/key.asc"
  export RELEASE_TAG_FINGERPRINTS="${tmp}/fingerprints"

  git init -q "$work"
  git -C "$work" config user.name "Release tag self-test"
  git -C "$work" config user.email "release-self-test@example.invalid"
  git -C "$work" config commit.gpgsign false
  git -C "$work" config tag.gpgSign false
  git -C "$work" config user.signingkey "$fpr"
  git -C "$work" config gpg.program "$(command -v gpg)"
  cargo_toml="${work}/Cargo.toml"
  printf '[package]\nversion = "0.1.0"\n' >"$cargo_toml"
  git -C "$work" add Cargo.toml
  git -C "$work" commit -q -m first
  local first
  first="$(git -C "$work" rev-parse HEAD)"
  export RELEASE_ROOT="$work"

  git -C "$work" tag v0.1.0 "$first"
  (cd "$work" && expect_failure "is lightweight" v0.1.0 "$first")
  git -C "$work" tag -d v0.1.0 >/dev/null

  git -C "$work" tag -a v0.1.0 -m "unsigned" "$first"
  (cd "$work" && expect_failure "unsigned" v0.1.0 "$first")
  git -C "$work" tag -d v0.1.0 >/dev/null

  git -C "$work" tag -s v0.1.0 -m "signed" "$first"
  (cd "$work" && bash "$SCRIPT_PATH" verify v0.1.0 "$first" >/dev/null)

  printf 'AEDA618886BF0331105B9CFCE4DC1F4A579505FB\n' >"${tmp}/fingerprints"
  (cd "$work" && expect_failure "unknown key" v0.1.0 "$first")
  printf '%s\n' "$fpr" >"${tmp}/fingerprints"

  git -C "$work" tag -s v0.2.0 -m "wrong version" "$first"
  (cd "$work" && expect_failure "does not match workspace version" v0.2.0 "$first")
  git -C "$work" tag -d v0.2.0 >/dev/null

  # Release candidates: the rc tag equals an rc workspace version, and a
  # final tag never releases an rc version.
  printf '[package]\nversion = "0.2.0-rc.1"\n' >"$cargo_toml"
  git -C "$work" commit -q -am rc
  local rc
  rc="$(git -C "$work" rev-parse HEAD)"
  git -C "$work" tag -s v0.2.0-rc.1 -m "rc" "$rc"
  (cd "$work" && bash "$SCRIPT_PATH" verify v0.2.0-rc.1 "$rc" >/dev/null)
  git -C "$work" tag -s v0.2.0 -m "final on rc" "$rc"
  (cd "$work" && expect_failure "does not match workspace version 0.2.0-rc.1" v0.2.0 "$rc")
  git -C "$work" tag -s v0.2.0-beta.x -m "bad suffix" "$rc"
  (cd "$work" && expect_failure "invalid release tag" v0.2.0-beta.x "$rc")

  # The release workflow passes the commit it will build; a tag for another
  # commit is refused.
  (cd "$work" && expect_failure "resolves to ${first}, expected ${rc}" v0.1.0 "$rc")

  ancestry_self_test "$work"

  gpgconf --kill gpg-agent >/dev/null 2>&1 || true
  rm -rf "$tmp" || true
  printf 'self-test passed\n'
}

case "${1:-}" in
  verify)
    shift
    [[ $# -ge 1 && $# -le 2 ]] || fail "usage: $0 verify <tag> [commit-sha]"
    verify_release_tag "$1" "${2:-}"
    ;;
  line)
    shift
    [[ $# -eq 1 ]] || fail "usage: $0 line <tag>"
    release_line "$1"
    ;;
  ancestry)
    shift
    [[ $# -eq 2 ]] || fail "usage: $0 ancestry <tag> <commit-sha>"
    verify_ancestry "$1" "$2"
    ;;
  self-test)
    [[ $# -eq 1 ]] || fail "usage: $0 self-test"
    self_test
    exit 0
    ;;
  *)
    fail "usage: $0 {verify <tag> [commit-sha]|line <tag>|ancestry <tag> <commit-sha>|self-test}"
    ;;
esac
