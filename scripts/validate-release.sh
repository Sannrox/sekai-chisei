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
dispatcher=".github/workflows/release-dispatch.yml"
[[ -f "$workflow" ]] || fail "missing ${workflow}"
[[ -f "$dispatcher" ]] || fail "missing ${dispatcher}"

# The dispatcher only turns a v* tag push into a main run of release.yml.
grep -F 'tags: ["v*"]' "$dispatcher" >/dev/null || fail "${dispatcher} must trigger on v* tags"
grep -F "actions: write" "$dispatcher" >/dev/null || fail "${dispatcher} must be able to dispatch workflows"
if grep -E '^\s*(-\s+)?uses:|workflow_dispatch|pull_request|contents: write' "$dispatcher" >/dev/null; then
  fail "${dispatcher} must only dispatch: no actions, other triggers, or write access"
fi
dispatch_runs="$(grep -E '^\s*(-\s+)?run:' "$dispatcher")"
[[ "$dispatch_runs" =~ ^[[:space:]]*run:\ gh\ workflow\ run\ release\.yml\ --ref\ main\ -f\ tag=\"\$TAG\"$ ]] \
  || fail "${dispatcher} must run only: gh workflow run release.yml --ref main -f tag=\"\$TAG\""

# release.yml runs from main for a tag input; a tag push never runs it.
if grep -E '^  push:|^\s+tags:' "$workflow" >/dev/null; then
  fail "${workflow} must not run on push; release-dispatch.yml starts it from main"
fi
grep -F "workflow_dispatch:" "$workflow" >/dev/null || fail "${workflow} must allow a non-tag dry-run"
grep -F 'group: release-${{ inputs.tag || github.ref }}' "$workflow" >/dev/null || fail "${workflow} must run one release per tag"
grep -F '[[ "$WORKFLOW_REF" == refs/heads/main ]]' "$workflow" >/dev/null || fail "${workflow} must refuse tagged runs that are not from main"
grep -F "ref: \${{ inputs.tag && format('refs/tags/{0}', inputs.tag) || '' }}" "$workflow" >/dev/null || fail "${workflow} must check out the release tag"
grep -F 'git fetch --force origin "refs/tags/${TAG}:refs/tags/${TAG}"' "$workflow" >/dev/null || fail "${workflow} must fetch the annotated tag object"
grep -F 'sha="$(git rev-parse "${TAG}^{commit}")"' "$workflow" >/dev/null || fail "${workflow} must resolve the tagged commit"
grep -F 'bash "${MAIN_TREE}/scripts/verify-release-tag.sh" verify "$TAG" "$sha"' "$workflow" >/dev/null || fail "${workflow} must verify the tag with main's verifier against the tagged commit"
grep -F 'RELEASE_TAG_FINGERPRINTS="${MAIN_TREE}/security/release-tag-fingerprints"' "$workflow" >/dev/null || fail "${workflow} must verify against main's allowed keys"
grep -F 'git merge-base --is-ancestor "$sha" refs/remotes/origin/main' "$workflow" >/dev/null || fail "${workflow} must require the tagged commit on main"
checkouts="$(grep -c 'uses: actions/checkout@' "$workflow")"
sha_checkouts="$(grep -c 'ref: ${{ needs.verify-tag.outputs.sha }}' "$workflow")"
head_checks="$(grep -c 'test "$(git rev-parse HEAD)" = "$SHA"' "$workflow")"
[[ "$checkouts" -eq $((sha_checkouts + 2)) ]] || fail "${workflow} must check out the release commit in every job after verify-tag"
[[ "$head_checks" -eq "$sha_checkouts" ]] || fail "${workflow} must check HEAD after every release-commit checkout"
if grep -E 'github\.sha|github\.ref_name|GITHUB_SHA|GITHUB_REF|github\.event_name' "$workflow" >/dev/null; then
  fail "${workflow} must use the tagged commit and tag input, not the event SHA or ref name"
fi
grep -F "changelog-notes.py" "$workflow" >/dev/null || fail "${workflow} must take GitHub Release notes from CHANGELOG"
grep -F "if: needs.verify-tag.outputs.tag != ''" "$workflow" >/dev/null || fail "${workflow} must gate publish/attest on a verified tag"
grep -F -- "--verify-tag" "$workflow" >/dev/null || fail "${workflow} must create the release for the existing tag"
grep -F '[[ "$TAG" == *-* ]]' "$workflow" >/dev/null || fail "${workflow} must treat a tag with - as a pre-release"
grep -F -- "kind=(--prerelease --latest=false)" "$workflow" >/dev/null || fail "${workflow} must draft a pre-release as never latest"
grep -F -- 'gh release edit "$TAG" --draft=false --prerelease --latest=false' "$workflow" >/dev/null || fail "${workflow} must publish a pre-release as never latest"
if grep -E -- '--latest( |$|")' "$workflow" >/dev/null; then
  fail "${workflow} must never force a release to latest"
fi
[[ "$(grep -c 'is already published; cut a new tag instead of re-running' "$workflow")" -ge 3 ]] \
  || fail "${workflow} must refuse a published release early, when drafting, and before publishing"
# "Re-run failed jobs" reuses verify-tag's outputs, so every job that changes a
# release or pushes an image refuses a published release itself.
python3 - "$workflow" <<'PY_JOBS' || fail "${workflow} must refuse a published release in every job that uploads, publishes, or pushes"
import re, sys
body = open(sys.argv[1]).read().split("\njobs:\n", 1)[1]
mutating = ("gh release upload", "gh release create", "gh release edit", "upload-rust-binary-action", "build/release.sh")
missing = [
    block.split(":", 1)[0].strip()
    for block in re.split(r"(?m)^(?=  [a-z][a-z0-9-]*:\n)", body)
    if any(m in block for m in mutating)
    and "is already published; cut a new tag instead of re-running" not in block
]
if missing:
    sys.exit("unguarded jobs: " + ", ".join(missing))
PY_JOBS
grep -F 'gh release delete-asset "$TAG" "$name" --yes' "$workflow" >/dev/null \
  || fail "${workflow} must drop an earlier run's assets when it resumes a draft"
grep -F "needs: [verify-tag, sekai-release, attest, compatibility-matrix, sekai-binaries, record-image-digest]" "$workflow" >/dev/null \
  || fail "${workflow} must publish only after every asset job, so a re-run can resume the draft"
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
