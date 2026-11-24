"""check-semver.py: the pull request and release-prep public-API gates."""

import contextlib
import io
import os
import pathlib
import subprocess
import tempfile
import unittest

from tests.release import ROOT, load

semver = load(ROOT / "scripts" / "check-semver.py")


def quiet(fn, *args, **kwargs):
    with contextlib.redirect_stdout(io.StringIO()):
        return fn(*args, **kwargs)


class Waiver(unittest.TestCase):
    def test_needs_a_breaking_marker_and_the_label(self):
        for title, body in (
            ("fix!: break", ""),
            ("fix(api)!: break", ""),
            ("fix: break", "### Breaking\n\nok\n"),
            ("fix: break", "### Upgrade\n\nok\n"),
            ("fix: break", "BREAKING CHANGE: gone\n"),
        ):
            with self.subTest(title=title, body=body):
                self.assertTrue(semver.breaking_waiver(title, body, ["risk:breaking"]))
        self.assertFalse(semver.breaking_waiver("fix!: break", "", []))
        self.assertFalse(semver.breaking_waiver("fix: break", "### Breaking\n", []))
        self.assertFalse(semver.breaking_waiver("fix: break", "", ["risk:breaking"]))
        self.assertFalse(semver.breaking_waiver("fix: break", "mentions Breaking inside prose", ["risk:breaking"]))


class Parsing(unittest.TestCase):
    def test_classifies_cargo_semver_checks_output(self):
        self.assertEqual(semver.classify_semver_output("ok", 0), "ok")
        self.assertEqual(semver.classify_semver_output("semver requires new major version\n", 1), "major")
        self.assertEqual(semver.classify_semver_output("semver requires new minor version\n", 1), "minor")
        self.assertEqual(semver.classify_semver_output("rustc exploded", 2), "error")

    def test_versions(self):
        self.assertEqual(semver.crate_major("1.5.0"), 1)
        self.assertEqual(semver.crate_major("v2.0.0"), 2)
        self.assertTrue(semver.major_bumped("2.0.0", "1.5.0"))
        self.assertFalse(semver.major_bumped("1.6.0", "1.5.0"))
        self.assertFalse(semver.major_bumped("1.5.0", "1.5.0"))
        self.assertEqual(semver.toml_package_version('[package]\nname = "x"\nversion = "1.4.0"\n'), "1.4.0")

    def test_finds_public_enums_and_their_non_exhaustive_marker(self):
        sample = (
            "/// docs\n#[derive(Debug)]\n#[non_exhaustive]\npub enum Marked {}\n\n"
            "#[derive(Clone)]\npub enum Bare {}\npub(crate) enum Hidden {}\n"
            "    pub enum Nested {}\n// pub enum Commented {}\n"
        )
        enums = semver.public_enums(sample)
        self.assertIn(("Marked", True), enums)
        self.assertIn(("Bare", False), enums)
        self.assertIn(("Nested", False), enums)
        self.assertNotIn("Hidden", [name for name, _ in enums])
        self.assertNotIn("Commented", [name for name, _ in enums])
        self.assertIn(("SameLine", True), semver.public_enums("#[non_exhaustive] pub enum SameLine {}\n"))

    def test_only_new_enums_need_non_exhaustive(self):
        base = {("src/lib.rs", "Old"): False}
        head = {("src/lib.rs", "Old"): False, ("src/lib.rs", "New"): False, ("src/other.rs", "Ok"): True}
        self.assertEqual(semver.new_enums_missing_non_exhaustive(base, head), ["src/lib.rs::New"])
        head["src/lib.rs", "New"] = True
        self.assertEqual(semver.new_enums_missing_non_exhaustive(base, head), [])


class LibraryPackages(unittest.TestCase):
    def test_skips_publish_false_and_binary_only_packages(self):
        root = pathlib.Path("/w")

        def package(name, publish, kinds):
            return {
                "name": name,
                "publish": publish,
                "manifest_path": f"/w/crates/{name}/Cargo.toml",
                "targets": [{"kind": kinds, "src_path": f"/w/crates/{name}/src/lib.rs"}],
            }

        metadata = {
            "packages": [
                package("published", None, ["lib"]),
                package("internal", [], ["lib"]),
                package("registry-only", ["internal-registry"], ["lib"]),
                package("tool", None, ["bin"]),
            ]
        }
        self.assertEqual(
            [name for name, _, _ in semver.library_packages(metadata, root)],
            ["published", "registry-only"],
        )


class Gates(unittest.TestCase):
    def test_pull_request_gate(self):
        for result, waived, missing, rc in (
            ("major", False, [], 1),
            ("major", True, [], 0),
            ("ok", False, ["src/lib.rs::New"], 1),
            ("error", False, [], 1),
            ("minor", False, [], 0),
        ):
            with self.subTest(result=result, waived=waived, missing=missing):
                self.assertEqual(quiet(semver.evaluate_pr, {"demo": result}, waived=waived, missing_enums=missing), rc)

    def test_release_gate_needs_a_major_bump_for_a_major_change(self):
        for result, versions, rc in (
            ("major", ("1.5.0", "1.5.0"), 1),
            ("major", ("2.0.0", "1.5.0"), 0),
            ("ok", ("1.5.0", "1.5.0"), 0),
            ("error", ("2.0.0", "1.5.0"), 1),
        ):
            with self.subTest(result=result, versions=versions):
                self.assertEqual(quiet(semver.evaluate_release, {"demo": result}, {"demo": versions}, "v1.5.0"), rc)


class LastFinalTag(unittest.TestCase):
    """The release baseline is the nearest final tag; an rc tag never starts it."""

    def setUp(self):
        tmp = tempfile.TemporaryDirectory(prefix=f"sv{os.getpid()}-")
        self.addCleanup(tmp.cleanup)
        self.work = pathlib.Path(tmp.name)
        self.git("init", "-q")
        self.git("config", "user.name", "check-semver")
        self.git("config", "user.email", "check-semver@example.invalid")
        self.git("config", "commit.gpgsign", "false")
        self.git("config", "tag.gpgSign", "false")
        self.git("commit", "-q", "--allow-empty", "-m", "first")
        self.git("tag", "-a", "v1.5.0", "-m", "v1.5.0")
        self.git("tag", "-a", "v1.6.0-rc.1", "-m", "rc")
        self.git("commit", "-q", "--allow-empty", "-m", "second")
        root = semver.ROOT
        semver.ROOT = self.work
        self.addCleanup(setattr, semver, "ROOT", root)

    def git(self, *args: str) -> None:
        subprocess.run(["git", "-C", str(self.work), *args], check=True, capture_output=True)

    def test_skips_release_candidates(self):
        self.assertEqual(semver.last_final_tag("HEAD^"), "v1.5.0")
        self.assertEqual(semver.last_final_tag("HEAD"), "v1.5.0")

    def test_a_tagged_commit_is_its_own_baseline_and_its_parent_is_not(self):
        self.git("tag", "-a", "v1.6.0", "-m", "v1.6.0")
        self.assertEqual(semver.last_final_tag("HEAD"), "v1.6.0")
        self.assertEqual(semver.last_final_tag("HEAD^"), "v1.5.0")

    def test_no_matching_final_tag_returns_none(self):
        self.git("tag", "-d", "v1.5.0")
        self.assertIsNone(semver.last_final_tag("HEAD"))

    def test_unknown_revision_stops_the_check(self):
        stderr = io.StringIO()
        with contextlib.redirect_stderr(stderr):
            with self.assertRaises(SystemExit) as caught:
                semver.last_final_tag("not-a-rev")
        self.assertEqual(caught.exception.code, 1)
        self.assertIn("Not a valid object name", stderr.getvalue())

    def test_a_shallow_repository_stops_the_check(self):
        clone = tempfile.TemporaryDirectory(prefix=f"svs{os.getpid()}-")
        self.addCleanup(clone.cleanup)
        subprocess.run(
            [
                "git",
                "clone",
                "--depth",
                "1",
                pathlib.Path(self.work).resolve().as_uri(),
                clone.name,
            ],
            check=True,
            capture_output=True,
        )
        semver.ROOT = pathlib.Path(clone.name)
        stderr = io.StringIO()
        with contextlib.redirect_stderr(stderr):
            with self.assertRaises(SystemExit) as caught:
                semver.last_final_tag("HEAD")
        self.assertEqual(caught.exception.code, 1)
        self.assertIn("No names found", stderr.getvalue())


if __name__ == "__main__":
    unittest.main()
