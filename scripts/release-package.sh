#!/usr/bin/env bash
# Write family release artifacts (SBOM, CHANGELOG notes, Tenkai manifest)
# into --out without publishing or attesting. Binary and image builds stay
# on the existing v* jobs; this path does not replace them.
#
# Usage:
#   bash scripts/release-package.sh --out dist [--tag vX.Y.Z] [--git-sha SHA]
#        [--skip-build] [--skip-test] [--skip-github] [--image name=sha256:...]
#        [--checksums-only]
set -euo pipefail

ROOT_PATH="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_PATH"

OUT=""
TAG=""
GIT_SHA=""
SKIP_BUILD=0
SKIP_TEST=0
SKIP_GITHUB=0
CHECKSUMS_ONLY=0
IMAGE_ARGS=()

fail() {
  printf 'release-package: %s\n' "$1" >&2
  exit 1
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --out) OUT="${2:-}"; shift 2 ;;
    --tag) TAG="${2:-}"; shift 2 ;;
    --git-sha) GIT_SHA="${2:-}"; shift 2 ;;
    --skip-build) SKIP_BUILD=1; shift ;;
    --skip-test) SKIP_TEST=1; shift ;;
    --skip-github) SKIP_GITHUB=1; shift ;;
    --checksums-only) CHECKSUMS_ONLY=1; shift ;;
    --image)
      [[ "${2:-}" == *=sha256:* ]] || fail "image must be name=sha256:..."
      image_tag="${2%%=*}"
      image_tag="${image_tag##*:}"
      [[ "$image_tag" == latest ]] && fail "must not produce a latest image tag"
      IMAGE_ARGS+=(--image "$2")
      shift 2
      ;;
    --with-images) fail "image digests are recorded with --image name=sha256:...; existing image jobs own the build" ;;
    *) fail "unknown argument: $1" ;;
  esac
done

[[ -n "$OUT" ]] || fail "usage: $0 --out dist [--tag vX.Y.Z] [--git-sha SHA]"
mkdir -p "$OUT"
OUT="$(cd "$OUT" && pwd)"

write_checksums() {
  python3 -c '
import hashlib, pathlib, sys
out = pathlib.Path(sys.argv[1])
skip = {"SHA256SUMS", "RELEASE_NOTES.md"}
lines = []
for path in sorted(p for p in out.iterdir() if p.is_file() and p.name not in skip):
    digest = hashlib.sha256(path.read_bytes()).hexdigest()
    lines.append(f"{digest}  {path.name}")
(out / "SHA256SUMS").write_text("\n".join(lines) + ("\n" if lines else ""))
' "$OUT"
}

if [[ "$CHECKSUMS_ONLY" -eq 1 ]]; then
  write_checksums
  cat "${OUT}/SHA256SUMS"
  exit 0
fi

workspace_version() {
  python3 -c 'import re,sys; from pathlib import Path; text=Path(sys.argv[1]).read_text(); m=re.search(r"(?ms)^\[package\][^\[]*?^version\s*=\s*\"([^\"]+)\"", text); sys.exit("Cargo.toml has no [package] version") if not m else print(m.group(1))' "$ROOT_PATH/Cargo.toml"
}

VERSION="$(workspace_version)"
if [[ -n "$TAG" ]]; then
  [[ "${TAG#v}" == "$VERSION" ]] || fail "tag ${TAG} does not match workspace version ${VERSION}"
  python3 "$ROOT_PATH/scripts/changelog-notes.py" "$VERSION" >"${OUT}/RELEASE_NOTES.md"
fi
if [[ -z "$GIT_SHA" ]]; then
  GIT_SHA="$(git rev-parse HEAD)"
fi
[[ "$GIT_SHA" =~ ^[0-9a-f]{40}$ ]] || fail "git sha must be a full lowercase SHA"

if [[ "$SKIP_TEST" -eq 0 ]]; then
  cargo test --locked --workspace
fi

if [[ "$SKIP_BUILD" -eq 0 ]]; then
  fail "binary builds stay on the existing v* jobs; pass --skip-build"
fi

python3 "$ROOT_PATH/scripts/release-sbom.py" "${OUT}/sekai-chisei.cdx.json"

LABEL_ARGS=()
if [[ -n "$TAG" && "$SKIP_GITHUB" -eq 0 ]]; then
  command -v gh >/dev/null 2>&1 || fail "gh is required for gate flags; pass --skip-github for a dry run"
  # Gate flags cover exactly the pull requests merged into the release commit
  # since the nearest final tag before it: an rc tag never starts the range,
  # or a final release would drop gates first seen in its release candidates,
  # and a pull request merged after the tagged commit never counts, even when a
  # retry runs days later.
  prev="$(git describe --tags --abbrev=0 --match 'v*' --exclude '*-*' "${GIT_SHA}^" 2>/dev/null || true)"
  range="$GIT_SHA"
  query="merged:<=$(TZ=UTC git log -1 --date=format-local:%Y-%m-%d --format=%cd "$GIT_SHA")"
  if [[ -n "$prev" ]]; then
    range="${prev}..${GIT_SHA}"
    query="merged:>=$(TZ=UTC git log -1 --date=format-local:%Y-%m-%d --format=%cd "$prev") ${query}"
  fi
  # A lookup failure or a truncated search fails the release: an empty or
  # partial list would publish a manifest without its gates.
  prs="$(gh pr list --state merged --limit 1000 --search "$query" --json mergeCommit,labels)" \
    || fail "could not list merged pull requests for gate flags"
  [[ "$(jq length <<<"$prs")" -lt 1000 ]] || fail "1000 or more merged pull requests match ${query}; gate flags would be incomplete"
  commits="$(git rev-list "$range")" || fail "could not list the commits in ${range}"
  labels="$(
    jq -r '.[] | select(.mergeCommit != null) | .mergeCommit.oid as $oid | .labels[] | "\($oid)\t\(.name)"' <<<"$prs" \
      | awk -F'\t' 'NR == FNR { in_range[$1] = 1; next } in_range[$1] { print $2 }' <(printf '%s\n' "$commits") - \
      | sort -u
  )" || fail "could not read gate flags from the merged pull requests"
  while IFS= read -r label; do
    [[ -n "$label" ]] && LABEL_ARGS+=(--label "$label")
  done <<<"$labels"
fi

python3 "$ROOT_PATH/scripts/release-manifest.py" \
  --component sekai-chisei \
  --version "$VERSION" \
  --git-sha "$GIT_SHA" \
  ${TAG:+--tag "$TAG"} \
  --dist "$OUT" \
  --out "${OUT}/sekai-chisei-release.json" \
  "${IMAGE_ARGS[@]}" \
  "${LABEL_ARGS[@]}"

write_checksums

echo "version=${VERSION}"
echo "artifacts in ${OUT}:"
cat "${OUT}/SHA256SUMS"
if [[ ${#IMAGE_ARGS[@]} -eq 0 ]]; then
  echo "images: none in this package"
else
  echo "images: ${#IMAGE_ARGS[@]} (version tags only, never latest)"
fi
