#!/usr/bin/env bash
# Local/CI checks for the v* release path. Does not publish or attest.
set -euo pipefail

ROOT_PATH="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_PATH"

fail() {
  printf 'validate-release: %s\n' "$1" >&2
  exit 1
}

python3 scripts/changelog-notes.py --self-test
python3 scripts/release-manifest.py --self-test
python3 scripts/release-sbom.py --self-test
bash scripts/verify-release-tag.sh self-test

workflow=".github/workflows/release.yml"
[[ -f "$workflow" ]] || fail "missing ${workflow}"
grep -F 'tags: ["v*"]' "$workflow" >/dev/null || fail "${workflow} must trigger on v* tags"
grep -F "workflow_dispatch:" "$workflow" >/dev/null || fail "${workflow} must allow a non-tag dry-run"
grep -F "changelog-notes.py" "$workflow" >/dev/null || fail "${workflow} must take GitHub Release notes from CHANGELOG"
grep -F "verify-release-tag.sh" "$workflow" >/dev/null || fail "${workflow} must verify the signed annotated tag"
grep -F "if: github.event_name == 'push' && startsWith(github.ref, 'refs/tags/v')" "$workflow" >/dev/null || fail "${workflow} must gate publish/attest on tag pushes"
grep -F "id-token: write" "$workflow" >/dev/null || fail "${workflow} must request id-token for provenance"
grep -F "attestations: write" "$workflow" >/dev/null || fail "${workflow} must request attestations permission"
grep -F "taiki-e/upload-rust-binary-action" "$workflow" >/dev/null || fail "${workflow} must keep the existing binary matrix"
grep -F "build/release-images.sh" "$workflow" >/dev/null || fail "${workflow} must keep the existing image jobs"
if grep -F "taiki-e/create-gh-release-action" "$workflow" >/dev/null; then
  fail "${workflow} must draft then publish from CHANGELOG instead of create-gh-release-action"
fi
head_perm="$(sed -n '1,/^jobs:/p' "$workflow")"
if printf '%s\n' "$head_perm" | grep -F "attestations: write" >/dev/null; then
  fail "${workflow} must not grant attestations: write at workflow level"
fi
if grep -E '(:latest|tag: latest|tags: latest)' "$workflow" >/dev/null; then
  fail "${workflow} must not produce a latest image tag"
fi
grep -F "never latest" "$workflow" >/dev/null || fail "${workflow} must say it never publishes latest"
grep -F "record-image-digest" "$workflow" >/dev/null || fail "${workflow} must record the image digest on the family manifest"
if grep -F 'dist/*' "$workflow" >/dev/null; then
  fail "${workflow} must upload explicit family artifacts, not dist/*"
fi
if grep -E '(:latest|tag: latest)' build/release.sh build/release-images.sh >/dev/null; then
  fail "image scripts must not produce a latest image tag"
fi

tmp="$(mktemp -d "${TMPDIR:-/tmp}/sekai-chisei-release-package.XXXXXX")"
trap 'rm -rf "$tmp"' EXIT
mkdir -p "${tmp}/dist"
printf 'fake\n' >"${tmp}/dist/sekai-1.4.0-test"
ROOT_PATH="$ROOT_PATH" bash scripts/release-package.sh --out "${tmp}/dist" --skip-build --skip-test --skip-github --git-sha "$(git rev-parse HEAD)"
[[ -f "${tmp}/dist/sekai-chisei-release.json" ]] || fail "dry-run package did not write a manifest"
[[ -f "${tmp}/dist/sekai-chisei.cdx.json" ]] || fail "dry-run package did not write an SBOM"
python3 -c "import json,sys; m=json.loads(open(sys.argv[1]).read()); assert m['schema']=='tenkai.family-release-manifest.v1'; assert m['component']=='sekai-chisei'; assert m['images']==[]; assert 'latest' not in json.dumps(m)" "${tmp}/dist/sekai-chisei-release.json"
python3 -c '
import json, sys
bom = json.loads(open(sys.argv[1]).read())
assert bom["bomFormat"] == "CycloneDX"
assert bom["metadata"]["component"]["name"] == "sekai-chisei"
for component in bom["components"]:
    for item in component.get("licenses") or []:
        license_id = (item.get("license") or {}).get("id")
        if license_id is not None:
            assert " " not in license_id and "OR" not in license_id, component["name"]
' "${tmp}/dist/sekai-chisei.cdx.json"
[[ ! -f "${tmp}/dist/published" ]] || fail "dry-run must not publish"

notes_out="${tmp}/notes"
mkdir -p "$notes_out"
bash scripts/release-package.sh --out "$notes_out" --skip-build --skip-test --skip-github --tag v1.4.0 --git-sha "$(git rev-parse HEAD)"
[[ -s "${notes_out}/RELEASE_NOTES.md" ]] || fail "tag dry-run did not write CHANGELOG notes"
grep -F "GATE:mig" "${notes_out}/RELEASE_NOTES.md" >/dev/null || fail "CHANGELOG notes missing expected 1.4.0 body"
grep -F "RELEASE_NOTES.md" "${notes_out}/SHA256SUMS" >/dev/null && fail "SHA256SUMS must not list RELEASE_NOTES.md"
grep -F "sekai-chisei-release.json" "${notes_out}/SHA256SUMS" >/dev/null || fail "SHA256SUMS must cover the family manifest"
bash scripts/release-package.sh --out "$notes_out" --checksums-only >/dev/null
grep -F "sekai-chisei-release.json" "${notes_out}/SHA256SUMS" >/dev/null || fail "checksums-only lost the family manifest"

if output="$(bash scripts/release-package.sh --out "${tmp}/dist" --skip-build --skip-test --skip-github --tag v9.9.9 --git-sha "$(git rev-parse HEAD)" 2>&1)"; then
  fail "expected tag/version mismatch to fail"
fi
[[ "$output" == *"does not match workspace version"* ]] || fail "mismatch failure missing expected message"

printf 'validate-release passed\n'
