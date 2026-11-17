"""package.sh dry runs against this repository, with a fake gh for gate flags."""

import json
import os
import pathlib
import shutil
import subprocess
import tempfile
import unittest

from tests.release import RELEASE, ROOT, load, load_release

SCRIPT = RELEASE / "package.sh"
notes = load_release("notes")
VERSION = load(ROOT / "scripts" / "check-semver.py").toml_package_version((ROOT / "Cargo.toml").read_text())
HEAD = subprocess.run(["git", "rev-parse", "HEAD"], cwd=ROOT, check=True, capture_output=True, text=True).stdout.strip()
DRY_RUN = ("--skip-build", "--skip-test", "--git-sha", HEAD)

# Answers `gh pr list` with $FAKE_PRS, or fails when $FAKE_PRS is "fail".
FAKE_GH = """#!/usr/bin/env bash
[[ "$FAKE_PRS" == fail ]] && { echo "HTTP 502" >&2; exit 1; }
printf '%s\\n' "$FAKE_PRS"
"""


class Package(unittest.TestCase):
    def setUp(self):
        tmp = tempfile.TemporaryDirectory(prefix=f"pkg{os.getpid()}-")
        self.addCleanup(tmp.cleanup)
        self.tmp = pathlib.Path(tmp.name)
        self.out = self.tmp / "dist"
        bin_dir = self.tmp / "bin"
        bin_dir.mkdir()
        (bin_dir / "gh").write_text(FAKE_GH)
        (bin_dir / "gh").chmod(0o755)
        self.env = {**os.environ, "PATH": f"{bin_dir}:{os.environ['PATH']}"}

    def package(self, *args: str, prs: list | str = "fail") -> subprocess.CompletedProcess:
        fake = prs if isinstance(prs, str) else json.dumps(prs)
        return subprocess.run(
            ["bash", str(SCRIPT), "--out", str(self.out), *args],
            env={**self.env, "FAKE_PRS": fake}, capture_output=True, text=True,
        )

    def manifest(self) -> dict:
        return json.loads((self.out / "sekai-chisei-release.json").read_text())

    def checksummed(self) -> set:
        return {line.split()[1] for line in (self.out / "SHA256SUMS").read_text().splitlines()}

    def test_dry_run_writes_a_manifest_and_sbom_without_images(self):
        result = self.package(*DRY_RUN, "--skip-github")
        self.assertEqual(result.returncode, 0, result.stderr)
        manifest = self.manifest()
        self.assertEqual(manifest["schema"], "tenkai.family-release-manifest.v1")
        self.assertEqual(manifest["component"], "sekai-chisei")
        self.assertEqual(manifest["images"], [])
        self.assertNotIn("latest", json.dumps(manifest))
        bom = json.loads((self.out / "sekai-chisei.cdx.json").read_text())
        self.assertEqual(bom["bomFormat"], "CycloneDX")
        self.assertEqual(bom["metadata"]["component"]["name"], "sekai-chisei")
        for component in bom["components"]:
            for item in component.get("licenses") or []:
                license_id = (item.get("license") or {}).get("id")
                if license_id is not None:
                    self.assertNotIn(" ", license_id, component["name"])

    def test_tag_dry_run_takes_notes_from_the_changelog_and_checksums_the_manifest(self):
        result = self.package(*DRY_RUN, "--skip-github", "--tag", f"v{VERSION}")
        self.assertEqual(result.returncode, 0, result.stderr)
        expected = notes.notes_for((ROOT / "CHANGELOG.md").read_text(), VERSION)
        self.assertEqual((self.out / "RELEASE_NOTES.md").read_text().strip(), expected.strip())
        self.assertIn("sekai-chisei-release.json", self.checksummed())
        self.assertNotIn("RELEASE_NOTES.md", self.checksummed())
        result = self.package("--checksums-only")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("sekai-chisei-release.json", self.checksummed())

    def test_refuses_a_tag_that_does_not_match_the_workspace_version(self):
        result = self.package(*DRY_RUN, "--skip-github", "--tag", "v9.9.9")
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("does not match workspace version", result.stderr)

    @unittest.skipUnless(shutil.which("jq"), "jq is required")
    def test_gate_flags_count_only_pull_requests_merged_into_the_release_commit(self):
        prs = [
            {"mergeCommit": {"oid": HEAD}, "labels": [{"name": "risk:breaking"}, {"name": "GATE:mig"}]},
            {"mergeCommit": {"oid": "0" * 40}, "labels": [{"name": "risk:realm"}]},
            {"mergeCommit": None, "labels": [{"name": "risk:realm"}]},
        ]
        result = self.package(*DRY_RUN, "--tag", f"v{VERSION}", prs=prs)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(self.manifest()["gate_flags"], ["breaking", "migration"])

    @unittest.skipUnless(shutil.which("jq"), "jq is required")
    def test_gate_flags_fail_closed(self):
        too_many = [{"mergeCommit": None, "labels": []}] * 1000
        for prs, message in (("fail", "could not list merged pull requests"), (too_many, "gate flags would be incomplete")):
            with self.subTest(message=message):
                result = self.package(*DRY_RUN, "--tag", f"v{VERSION}", prs=prs)
                self.assertNotEqual(result.returncode, 0)
                self.assertIn(message, result.stderr)


if __name__ == "__main__":
    unittest.main()
