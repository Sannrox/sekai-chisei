"""PostgreSQL harnesses stop on INT/TERM instead of resuming after cleanup (#2832).

`trap cleanup EXIT INT TERM` runs cleanup and then continues, so an interrupt
during the readiness wait can keep going against a stopped database.
"""

import os
import pathlib
import signal
import stat
import subprocess
import tempfile
import time
import unittest

SCRIPTS = pathlib.Path(__file__).resolve().parents[1]

HARNESSES = (
    ("object-path-with-postgres.sh", True),
    ("postgres_portfolio_tests_apple.sh", False),
    ("postgres_reusable_sekai_tests.sh", False),
    ("postgres-conformance.sh", False),
)

FAKE_CLI = r"""#!/usr/bin/env python3
import os, sys, time
from pathlib import Path
state = Path(os.environ["HARNESS_TEST_STATE"])
args = sys.argv[1:]
if not args:
    raise SystemExit(2)
cmd = args[0]
if cmd == "system":
    raise SystemExit(0)
if cmd == "run":
    raise SystemExit(0)
if cmd in ("rm", "delete"):
    raise SystemExit(0)
if cmd == "stop":
    with (state / "stops").open("a") as fh:
        fh.write("stop\n")
    raise SystemExit(0)
if cmd == "exec":
    rest = args[1:]
    if any(token == "pg_isready" or token.endswith("/pg_isready") for token in rest):
        (state / "in_wait").write_text("1")
        if (state / "ready_ok").exists():
            raise SystemExit(0)
        time.sleep(0.2)
        raise SystemExit(1)
    raise SystemExit(0)
raise SystemExit(0)
"""

FAKE_OPENSSL = r"""#!/usr/bin/env python3
import sys
from pathlib import Path
args = sys.argv[1:]
i = 0
while i < len(args):
    if args[i] in ("-out", "-keyout") and i + 1 < len(args):
        path = Path(args[i + 1])
        path.parent.mkdir(parents=True, exist_ok=True)
        path.touch()
        i += 2
        continue
    i += 1
"""

FAKE_CARGO = r"""#!/usr/bin/env python3
import os
from pathlib import Path
Path(os.environ["HARNESS_TEST_STATE"], "later").write_text("cargo")
"""

FAKE_LATER = r"""#!/usr/bin/env python3
import os
from pathlib import Path
Path(os.environ["HARNESS_TEST_STATE"], "later").write_text("cmd")
"""


def _chmodx(path: pathlib.Path) -> None:
    path.chmod(path.stat().st_mode | stat.S_IXUSR)


class HarnessSignals(unittest.TestCase):
    def setUp(self):
        tmp = tempfile.TemporaryDirectory(prefix=f"pgsig{os.getpid()}-")
        self.addCleanup(tmp.cleanup)
        self.state = pathlib.Path(tmp.name)
        bindir = self.state / "bin"
        bindir.mkdir()
        (bindir / "cli.py").write_text(FAKE_CLI)
        _chmodx(bindir / "cli.py")
        for name in ("docker", "container"):
            (bindir / name).symlink_to(bindir / "cli.py")
        (bindir / "openssl").write_text(FAKE_OPENSSL)
        _chmodx(bindir / "openssl")
        (bindir / "cargo").write_text(FAKE_CARGO)
        _chmodx(bindir / "cargo")
        (bindir / "later").write_text(FAKE_LATER)
        _chmodx(bindir / "later")
        self.env = {
            **os.environ,
            "PATH": f"{bindir}{os.pathsep}{os.environ['PATH']}",
            "HARNESS_TEST_STATE": str(self.state),
            "SEKAI_TEST_POSTGRES_PORT": "55432",
            "SEKAI_CONTAINER_CLI": "docker",
        }

    def _start(self, script, needs_command):
        cmd = ["bash", str(SCRIPTS / script)]
        if needs_command:
            cmd.append(str(self.state / "bin" / "later"))
        return subprocess.Popen(
            cmd,
            env=self.env,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )

    def _wait_for_readiness(self, proc):
        marker = self.state / "in_wait"
        deadline = time.time() + 10
        while time.time() < deadline:
            if marker.exists():
                return
            if proc.poll() is not None:
                out, err = proc.communicate()
                self.fail(f"exited {proc.returncode} before readiness wait:\n{err}\n{out}")
            time.sleep(0.05)
        proc.kill()
        out, err = proc.communicate()
        self.fail(f"never reached readiness wait:\n{err}\n{out}")

    def _stops(self):
        path = self.state / "stops"
        if not path.exists():
            return 0
        return len(path.read_text().splitlines())

    def test_int_during_readiness_stops_with_130(self):
        for script, needs_command in HARNESSES:
            with self.subTest(script=script):
                for leftover in ("in_wait", "stops", "later", "ready_ok"):
                    path = self.state / leftover
                    if path.exists():
                        path.unlink()
                proc = self._start(script, needs_command)
                self._wait_for_readiness(proc)
                proc.send_signal(signal.SIGINT)
                try:
                    stdout, stderr = proc.communicate(timeout=3)
                except subprocess.TimeoutExpired:
                    proc.kill()
                    proc.communicate()
                    self.fail(f"{script} kept running after INT")
                self.assertEqual(proc.returncode, 130, stderr or stdout)
                self.assertEqual(self._stops(), 1, "cleanup must run once")
                self.assertFalse((self.state / "later").exists(), "later step ran")

    def test_term_during_readiness_stops_with_143(self):
        proc = self._start("postgres_portfolio_tests_apple.sh", False)
        self._wait_for_readiness(proc)
        proc.send_signal(signal.SIGTERM)
        try:
            stdout, stderr = proc.communicate(timeout=3)
        except subprocess.TimeoutExpired:
            proc.kill()
            proc.communicate()
            self.fail("kept running after TERM")
        self.assertEqual(proc.returncode, 143, stderr or stdout)
        self.assertEqual(self._stops(), 1)
        self.assertFalse((self.state / "later").exists())

    def test_normal_exit_still_cleans_up(self):
        (self.state / "ready_ok").write_text("1")
        proc = self._start("object-path-with-postgres.sh", True)
        stdout, stderr = proc.communicate(timeout=10)
        self.assertEqual(proc.returncode, 0, stderr or stdout)
        self.assertEqual((self.state / "later").read_text(), "cmd")
        self.assertEqual(self._stops(), 1)
