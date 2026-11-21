"""A failed git diff runs the optional lane instead of skipping it (#2807)."""

import os
import pathlib
import subprocess
import tempfile
import unittest

SCRIPT = pathlib.Path(__file__).resolve().parents[1] / "ci" / "path-scope.sh"


class PathScope(unittest.TestCase):
    def setUp(self):
        tmp = tempfile.TemporaryDirectory(prefix=f"ps{os.getpid()}-")
        self.addCleanup(tmp.cleanup)
        self.work = pathlib.Path(tmp.name)
        self.out = self.work / "github-output"
        self.git("init", "-q", "-b", "main")
        self.git("config", "user.name", "path-scope")
        self.git("config", "user.email", "path-scope@example.invalid")
        self.git("config", "commit.gpgsign", "false")
        (self.work / "README").write_text("base\n")
        self.git("add", "README")
        self.git("commit", "-q", "-m", "base")
        self.base = self.git("rev-parse", "HEAD")

    def git(self, *args):
        result = subprocess.run(
            ["git", "-C", str(self.work), *args],
            check=True,
            capture_output=True,
            text=True,
        )
        return result.stdout.strip()

    def run_script(self, pattern, *, event="pull_request", base=None, key="images"):
        self.out.write_text("")
        env = {
            **os.environ,
            "GITHUB_EVENT_NAME": event,
            "BASE": self.base if base is None else base,
            "GITHUB_OUTPUT": str(self.out),
        }
        result = subprocess.run(
            ["bash", str(SCRIPT), key, pattern],
            cwd=self.work,
            env=env,
            capture_output=True,
            text=True,
        )
        value = None
        for line in self.out.read_text().splitlines():
            if line.startswith(f"{key}="):
                value = line.split("=", 1)[1]
        return result, value

    def test_matching_diff_runs_the_lane(self):
        build = self.work / "build"
        build.mkdir()
        (build / "Dockerfile").write_text("from scratch\n")
        self.git("add", "build/Dockerfile")
        self.git("commit", "-q", "-m", "image")
        result, value = self.run_script(r"^build/")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(value, "true")

    def test_non_matching_diff_skips_the_lane(self):
        (self.work / "docs.md").write_text("n\n")
        self.git("add", "docs.md")
        self.git("commit", "-q", "-m", "docs")
        result, value = self.run_script(r"^build/")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(value, "false")

    def test_failed_diff_runs_the_lane(self):
        (self.work / "docs.md").write_text("n\n")
        self.git("add", "docs.md")
        self.git("commit", "-q", "-m", "docs")
        result, value = self.run_script(r"^build/", base="missing-base")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(value, "true")
