"""verify-tag.sh against real annotated, signed, and lightweight tags in a scratch repository."""

import os
import pathlib
import shutil
import subprocess
import tempfile
import unittest

from tests.release import RELEASE

SCRIPT = RELEASE / "verify-tag.sh"


@unittest.skipUnless(shutil.which("gpg"), "gpg is required")
class VerifyTag(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        # Short base path: gpg-agent socket paths have a length limit.
        cls.tmp = pathlib.Path(tempfile.mkdtemp(prefix=f"vt{os.getpid()}-", dir="/tmp"))
        gnupg = cls.tmp / "g"
        gnupg.mkdir(mode=0o700)
        (gnupg / "gpg.conf").write_text("pinentry-mode loopback\n")
        (gnupg / "gpg-agent.conf").write_text("allow-loopback-pinentry\n")
        cls.env = {**os.environ, "GNUPGHOME": str(gnupg)}
        subprocess.run(
            ["gpg", "--batch", "--pinentry-mode", "loopback", "--passphrase", "",
             "--quick-generate-key", "Release test <release-test@example.invalid>",
             "ed25519", "default", "never"],
            env=cls.env, check=True, capture_output=True,
        )
        listing = subprocess.run(
            ["gpg", "--batch", "--list-secret-keys", "--with-colons"],
            env=cls.env, check=True, capture_output=True, text=True,
        ).stdout
        cls.fpr = next(line.split(":")[9] for line in listing.splitlines() if line.startswith("fpr:"))
        key = cls.tmp / "key.asc"
        key.write_bytes(subprocess.run(
            ["gpg", "--batch", "--armor", "--export", cls.fpr],
            env=cls.env, check=True, capture_output=True,
        ).stdout)
        cls.fingerprints = cls.tmp / "fingerprints"
        cls.work = cls.tmp / "w"
        cls.env.update(
            RELEASE_TAG_KEY=str(key),
            RELEASE_TAG_FINGERPRINTS=str(cls.fingerprints),
            RELEASE_ROOT=str(cls.work),
        )
        subprocess.run(["git", "init", "-q", "-b", "main", str(cls.work)], env=cls.env, check=True)
        for k, v in {
            "user.name": "Release test", "user.email": "release-test@example.invalid",
            "commit.gpgsign": "false", "tag.gpgSign": "false",
            "user.signingkey": cls.fpr, "gpg.program": shutil.which("gpg"),
        }.items():
            cls.git("config", k, v)
        cargo = cls.work / "Cargo.toml"
        cargo.write_text('[package]\nversion = "0.1.0"\n')
        cls.git("add", "Cargo.toml")
        cls.git("commit", "-q", "-m", "first")
        cls.first = cls.git("rev-parse", "HEAD")
        cls.git("tag", "-a", "v0.0.9", "-m", "unsigned", cls.first)
        cls.git("tag", "-s", "v0.1.0", "-m", "signed", cls.first)
        cls.git("tag", "-s", "v0.2.0", "-m", "wrong version", cls.first)
        cargo.write_text('[package]\nversion = "0.2.0-rc.1"\n')
        cls.git("commit", "-q", "-am", "rc")
        cls.rc = cls.git("rev-parse", "HEAD")
        cls.git("tag", "-s", "v0.2.0-rc.1", "-m", "rc", cls.rc)
        cls.git("tag", "-s", "v0.2.1", "-m", "final on rc", cls.rc)
        cls.git("tag", "-s", "v0.2.0-beta.x", "-m", "bad suffix", cls.rc)
        cls.git("checkout", "-q", cls.first)

    @classmethod
    def git(cls, *args: str) -> str:
        return subprocess.run(
            ["git", "-C", str(cls.work), *args], env=cls.env, check=True, capture_output=True, text=True,
        ).stdout.strip()

    @classmethod
    def tearDownClass(cls):
        subprocess.run(["gpgconf", "--kill", "gpg-agent"], env=cls.env, capture_output=True)
        shutil.rmtree(cls.tmp, ignore_errors=True)

    def setUp(self):
        self.fingerprints.write_text(self.fpr + "\n")

    def run_script(self, *args: str, env: dict | None = None) -> subprocess.CompletedProcess:
        return subprocess.run(
            ["bash", str(SCRIPT), *args], cwd=self.work, env={**self.env, **(env or {})},
            capture_output=True, text=True,
        )

    def assertRefused(self, result: subprocess.CompletedProcess, message: str):
        self.assertNotEqual(result.returncode, 0, result.stdout)
        self.assertIn(message, result.stderr)

    def test_accepts_a_signed_tag_matching_the_workspace_version(self):
        result = self.run_script("verify", "v0.1.0", self.first)
        self.assertEqual(result.returncode, 0, result.stderr)

    def test_refuses_a_lightweight_tag(self):
        self.git("tag", "-f", "v0.4.0", self.first)
        self.assertRefused(self.run_script("verify", "v0.4.0", self.first), "is lightweight")

    def test_refuses_an_unsigned_tag(self):
        self.assertRefused(self.run_script("verify", "v0.0.9", self.first), "unsigned")

    def test_refuses_an_unknown_key(self):
        self.fingerprints.write_text("AEDA618886BF0331105B9CFCE4DC1F4A579505FB\n")
        self.assertRefused(self.run_script("verify", "v0.1.0", self.first), "unknown key")

    def test_refuses_a_tag_that_does_not_match_the_workspace_version(self):
        self.assertRefused(self.run_script("verify", "v0.2.0", self.first), "does not match workspace version")

    def test_release_candidate_tag_matches_an_rc_version_only(self):
        self.git("checkout", "-q", self.rc)
        self.addCleanup(self.git, "checkout", "-q", self.first)
        self.assertEqual(self.run_script("verify", "v0.2.0-rc.1", self.rc).returncode, 0)
        self.assertRefused(self.run_script("verify", "v0.2.1", self.rc), "does not match workspace version 0.2.0-rc.1")
        self.assertRefused(self.run_script("verify", "v0.2.0-beta.x", self.rc), "invalid release tag")

    def test_refuses_a_tag_for_another_commit(self):
        self.assertRefused(self.run_script("verify", "v0.1.0", self.rc), f"resolves to {self.first}, expected {self.rc}")

    def run_with_recorded_status(self, status: str, exit_code: int) -> subprocess.CompletedProcess:
        """Run `verify v0.1.0` with `git verify-tag` replaced by recorded status output and exit code."""
        shim = pathlib.Path(tempfile.mkdtemp(prefix="shim-", dir=self.tmp))
        self.addCleanup(shutil.rmtree, shim, True)
        (shim / "status").write_text(status)
        git = shim / "git"
        git.write_text(
            "#!/usr/bin/env bash\n"
            f'if [[ "$1" == verify-tag ]]; then cat {shim / "status"}; exit {exit_code}; fi\n'
            f'exec {shutil.which("git")} "$@"\n'
        )
        git.chmod(0o755)
        return self.run_script("verify", "v0.1.0", self.first, env={"PATH": f"{shim}:{os.environ['PATH']}"})

    def status(self, *lines: str) -> str:
        validsig = f"[GNUPG:] VALIDSIG {self.fpr} 2026-01-01 1767225600 0 4 0 22 10 00 {self.fpr}"
        good = f"[GNUPG:] GOODSIG {self.fpr[-16:]} Release test"
        return "\n".join([f"[GNUPG:] NEWSIG", *lines, good, validsig]) + "\n"

    def test_recorded_good_status_passes(self):
        result = self.run_with_recorded_status(self.status(), 0)
        self.assertEqual(result.returncode, 0, result.stderr)

    def test_refuses_revoked_or_expired_status_even_with_validsig(self):
        for keyword in ("REVKEYSIG", "EXPKEYSIG", "EXPSIG", "BADSIG", "ERRSIG"):
            with self.subTest(keyword=keyword):
                status = self.status(f"[GNUPG:] {keyword} {self.fpr[-16:]} Release test")
                self.assertRefused(self.run_with_recorded_status(status, 0), f"signature status is {keyword}")

    def test_refuses_a_failing_verify_tag_exit_regardless_of_output(self):
        self.assertRefused(self.run_with_recorded_status(self.status(), 1), "signature is not valid")


class Ancestry(unittest.TestCase):
    """A release commit must be on main or on its own release-X.Y line."""

    def setUp(self):
        tmp = tempfile.TemporaryDirectory(prefix=f"anc{os.getpid()}-")
        self.addCleanup(tmp.cleanup)
        self.work = pathlib.Path(tmp.name)
        self.env = {**os.environ, "RELEASE_REF_PREFIX": "refs/heads/"}
        self.git("init", "-q", "-b", "main")
        self.git("config", "user.name", "Release test")
        self.git("config", "user.email", "release-test@example.invalid")
        self.git("config", "commit.gpgsign", "false")
        base = self.commit("base")
        self.on_main = self.commit("on-main")
        self.on_line = self.commit("on-line", branch="release-2.0", start=base)
        self.on_other_line = self.commit("on-other-line", branch="release-2.1", start=base)
        self.on_feature = self.commit("on-feature", branch="feature", start=base)

    def git(self, *args: str) -> str:
        return subprocess.run(
            ["git", "-C", str(self.work), *args], env=self.env, check=True, capture_output=True, text=True,
        ).stdout.strip()

    def commit(self, message: str, branch: str | None = None, start: str | None = None) -> str:
        if branch:
            self.git("checkout", "-q", "-b", branch, start)
        self.git("commit", "-q", "--allow-empty", "-m", message)
        return self.git("rev-parse", "HEAD")

    def run_script(self, *args: str) -> subprocess.CompletedProcess:
        return subprocess.run(["bash", str(SCRIPT), *args], cwd=self.work, env=self.env, capture_output=True, text=True)

    def test_maps_a_tag_to_its_release_line(self):
        for tag, line in (("v2.0.1", "release-2.0"), ("v2.1.0-rc.1", "release-2.1"), ("v0.1.5", "release-0.1")):
            with self.subTest(tag=tag):
                self.assertEqual(self.run_script("line", tag).stdout.strip(), line)

    def test_accepts_main_and_the_tags_own_line(self):
        for commit in (self.on_main, self.on_line):
            with self.subTest(commit=commit):
                result = self.run_script("ancestry", "v2.0.1", commit)
                self.assertEqual(result.returncode, 0, result.stderr)

    def test_refuses_another_line_or_a_feature_branch(self):
        for commit in (self.on_other_line, self.on_feature):
            with self.subTest(commit=commit):
                result = self.run_script("ancestry", "v2.0.1", commit)
                self.assertNotEqual(result.returncode, 0)
                self.assertIn("on neither main nor release-2.0", result.stderr)
        self.assertNotEqual(self.run_script("ancestry", "v2.1.1", self.on_line).returncode, 0)


if __name__ == "__main__":
    unittest.main()
