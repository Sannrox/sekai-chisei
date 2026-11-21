"""Gateway smoke dumps the live gateway log after startup (#2850).

A copy of gateway-$attempt.log taken once the listener answers omits lines
written during a later failed request.
"""

import os
import pathlib
import stat
import subprocess
import tempfile
import textwrap
import unittest

SCRIPT = pathlib.Path(__file__).resolve().parents[1] / "chisei_gateway_smoke.sh"
POST_START = "post-start gateway log line"


def _chmodx(path: pathlib.Path) -> None:
    path.chmod(path.stat().st_mode | stat.S_IXUSR)


class GatewaySmokeLog(unittest.TestCase):
    def test_failed_request_dump_includes_lines_written_after_startup(self):
        tmp = tempfile.TemporaryDirectory(prefix=f"gwlog{os.getpid()}-")
        self.addCleanup(tmp.cleanup)
        bindir = pathlib.Path(tmp.name) / "bin"
        bindir.mkdir()

        (bindir / "sekai-chisei").write_text(
            textwrap.dedent(
                """\
                #!/usr/bin/env python3
                import os, time
                from pathlib import Path
                Path(os.environ["SEKAI_SOCKET"]).touch()
                time.sleep(3600)
                """
            )
        )
        (bindir / "sekaictl").write_text("#!/bin/sh\nexit 0\n")
        (bindir / "chisei-gateway").write_text(
            textwrap.dedent(
                f"""\
                #!/usr/bin/env python3
                import os, sys
                from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

                host, port = os.environ["GATEWAY_BIND"].rsplit(":", 1)

                class Handler(BaseHTTPRequestHandler):
                    def do_GET(self):
                        self.send_response(200)
                        self.end_headers()
                    def do_POST(self):
                        length = int(self.headers.get("content-length", "0"))
                        self.rfile.read(length)
                        print({POST_START!r}, file=sys.stderr, flush=True)
                        self.send_response(400)
                        self.end_headers()
                    def log_message(self, *_args):
                        pass

                ThreadingHTTPServer((host, int(port)), Handler).serve_forever()
                """
            )
        )
        for name in ("sekai-chisei", "sekaictl", "chisei-gateway"):
            _chmodx(bindir / name)

        env = {
            **os.environ,
            "CHISEI_GATEWAY_SMOKE_SKIP_BUILD": "1",
            "CHISEI_GATEWAY_SMOKE_BIN_DIR": str(bindir),
            "CHISEI_GATEWAY_SMOKE_LIVE_CLIENTS": "0",
        }
        result = subprocess.run(
            ["bash", str(SCRIPT)],
            env=env,
            capture_output=True,
            text=True,
            timeout=30,
        )
        self.assertNotEqual(result.returncode, 0, result.stdout)
        combined = result.stderr + result.stdout
        self.assertIn(POST_START, combined, combined[-2000:])
