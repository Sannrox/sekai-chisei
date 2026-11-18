"""Tests for scripts/chisei_gateway_live_clients.sh."""

import os
import pathlib
import subprocess
import tempfile
import unittest

SCRIPT = pathlib.Path(__file__).resolve().parents[1] / "chisei_gateway_live_clients.sh"


class DoctorTest(unittest.TestCase):
    def test_missing_codex_profile_is_reported_and_later_checks_still_run(self):
        with tempfile.TemporaryDirectory() as home:
            env = {
                **os.environ,
                "HOME": home,
                "CODEX_HOME": home,
                # A closed local port makes the gateway check fail fast.
                "GATEWAY_BASE_URL": "http://127.0.0.1:1/v1",
            }
            result = subprocess.run(
                ["bash", str(SCRIPT), "doctor"],
                env=env,
                capture_output=True,
                text=True,
                timeout=60,
            )
        self.assertEqual(result.returncode, 1, result.stderr)
        self.assertIn("install-codex-profile", result.stderr)
        self.assertIn("gateway did not answer", result.stderr)
        self.assertIn("doctor failed", result.stderr)

    def test_check_codex_profile_still_exits_non_zero_when_missing(self):
        with tempfile.TemporaryDirectory() as home:
            env = {**os.environ, "HOME": home, "CODEX_HOME": home}
            result = subprocess.run(
                ["bash", str(SCRIPT), "check-codex-profile"],
                env=env,
                capture_output=True,
                text=True,
                timeout=60,
            )
        self.assertEqual(result.returncode, 2, result.stderr)
        self.assertIn("missing Codex config", result.stderr)


class ClaudeSmokeTest(unittest.TestCase):
    """The smoke commands run under the system bash (3.2 on macOS) with `set -u`."""

    def run_smoke(self, command, model):
        shell = "/bin/bash" if os.path.exists("/bin/bash") else "bash"
        with tempfile.TemporaryDirectory() as stub_dir:
            stub = pathlib.Path(stub_dir) / "claude"
            stub.write_text('#!/bin/sh\necho "claude-args: $*"\n')
            stub.chmod(0o755)
            env = {**os.environ, "PATH": f"{stub_dir}:{os.environ['PATH']}"}
            env.pop("CHISEI_CLAUDE_MODEL", None)
            if model:
                env["CHISEI_CLAUDE_MODEL"] = model
            return subprocess.run(
                [shell, str(SCRIPT), command],
                env=env,
                capture_output=True,
                text=True,
                timeout=60,
            )

    def test_smoke_commands_run_without_a_model(self):
        for command in ("claude-smoke", "claude-key-smoke"):
            with self.subTest(command=command):
                result = self.run_smoke(command, None)
                self.assertEqual(result.returncode, 0, result.stderr)
                self.assertNotIn("--model", result.stdout)

    def test_smoke_commands_pass_the_model_through(self):
        for command in ("claude-smoke", "claude-key-smoke"):
            with self.subTest(command=command):
                result = self.run_smoke(command, "claude-test-model")
                self.assertEqual(result.returncode, 0, result.stderr)
                self.assertIn("--model claude-test-model", result.stdout)


if __name__ == "__main__":
    unittest.main()
