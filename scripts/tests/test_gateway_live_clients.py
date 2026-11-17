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


if __name__ == "__main__":
    unittest.main()
