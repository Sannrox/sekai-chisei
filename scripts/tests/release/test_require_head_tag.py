"""A commit with two tags is accepted for the tag being released (#2810)."""

import os
import pathlib
import subprocess
import tempfile
import unittest

from tests.release import RELEASE

SCRIPT = RELEASE / "require-head-tag.sh"


class RequireHeadTag(unittest.TestCase):
    def setUp(self):
        tmp = tempfile.TemporaryDirectory(prefix=f"rht{os.getpid()}-")
        self.addCleanup(tmp.cleanup)
        self.work = pathlib.Path(tmp.name)
        self.git("init", "-q", "-b", "main")
        self.git("config", "user.name", "require-head-tag")
        self.git("config", "user.email", "require-head-tag@example.invalid")
        self.git("config", "commit.gpgsign", "false")
        self.git("config", "tag.gpgSign", "false")
        self.git("commit", "-q", "--allow-empty", "-m", "release")
        self.git("tag", "-a", "v1.0.0-rc.1", "-m", "rc")
        self.git("tag", "-a", "v1.0.0", "-m", "final")

    def git(self, *args):
        return subprocess.run(
            ["git", "-C", str(self.work), *args],
            check=True,
            capture_output=True,
            text=True,
        ).stdout.strip()

    def run_script(self, tag):
        return subprocess.run(
            ["bash", str(SCRIPT), tag],
            cwd=self.work,
            capture_output=True,
            text=True,
        )

    def test_both_tags_on_the_commit_are_accepted(self):
        described = self.git("describe", "--tags", "--exact-match", "HEAD")
        self.assertIn(described, {"v1.0.0", "v1.0.0-rc.1"})
        other = next(tag for tag in ("v1.0.0", "v1.0.0-rc.1") if tag != described)
        # Old guard: test "$(git describe --tags --exact-match HEAD)" = "$TAG"
        self.assertNotEqual(described, other)
        for tag in ("v1.0.0", "v1.0.0-rc.1"):
            with self.subTest(tag=tag):
                result = self.run_script(tag)
                self.assertEqual(result.returncode, 0, result.stderr)

    def test_a_tag_on_another_commit_is_refused(self):
        self.git("commit", "-q", "--allow-empty", "-m", "later")
        self.git("tag", "-a", "v1.0.1", "-m", "later")
        result = self.run_script("v1.0.0")
        self.assertNotEqual(result.returncode, 0, result.stdout)
        self.assertIn("v1.0.0", result.stderr)
