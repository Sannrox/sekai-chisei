#!/usr/bin/env bash
# Record the pushed image's digest on the draft release's family manifest and
# refresh its checksums. Run from the tagged commit with GH_TOKEN, GH_REPO,
# and DOCKER_REGISTRY set, after the image manifest is pushed.
#
# Usage: bash scripts/release/record-image-digest.sh <tag>
set -euo pipefail

fail() {
  printf 'record-image-digest: %s\n' "$1" >&2
  exit 1
}

[[ $# -eq 1 ]] || fail "usage: $0 <tag>"
tag="$1"
[[ -n "${DOCKER_REGISTRY:-}" ]] || fail "DOCKER_REGISTRY is required"
here="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"

registry="$(printf '%s' "$DOCKER_REGISTRY" | tr '[:upper:]' '[:lower:]')"
version="${tag/+/_}"
image="${registry}:${version}"
gateway_registry="$(printf '%s' "${registry}/chisei-gateway" | tr '[:upper:]' '[:lower:]')"
gateway_image="${gateway_registry}:${version}"
[[ "${image##*:}" != latest ]] || fail "must not produce a latest image tag"
[[ "${gateway_image##*:}" != latest ]] || fail "must not produce a latest image tag"
# Structured read, no pipe: an awk that exits on the Digest line can end the
# producer early under pipefail (#2085). A bare `{{.Manifest.Digest}}` falls
# back to the full text output, so printf.
digest="$(docker buildx imagetools inspect "$image" --format '{{printf "%s" .Manifest.Digest}}')"
[[ "$digest" == sha256:* ]] || fail "missing digest for ${image}"
gateway_digest="$(docker buildx imagetools inspect "$gateway_image" --format '{{printf "%s" .Manifest.Digest}}')"
[[ "$gateway_digest" == sha256:* ]] || fail "missing digest for ${gateway_image}"

mkdir -p dist
bash "${here}/github-release.sh" download "$tag" dist sekai-chisei-release.json sekai-chisei.cdx.json
python3 "${here}/record.py" image dist/sekai-chisei-release.json "$image" "$digest"
python3 "${here}/record.py" image dist/sekai-chisei-release.json "$gateway_image" "$gateway_digest"
bash "${here}/package.sh" --out dist --checksums-only
bash "${here}/github-release.sh" upload "$tag" dist/sekai-chisei-release.json dist/SHA256SUMS
echo "Image tags: version only, never latest"
