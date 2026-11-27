"""The relational snapshot rehearsal starts a pinned fixture image (#2358).

The command must pin ghcr.io/sannrox/keiko:v0.1.0, generate compose from that
image with no build, isolate the plane on unique ports, and invoke the driver
with the edge flags. It never vendors the fixture into this repository.
"""

import pathlib
import re
import subprocess
import unittest

SCRIPTS = pathlib.Path(__file__).resolve().parents[1]
SCRIPT = SCRIPTS / "keiko_relational_rehearsal.sh"
DRIVER = (
    SCRIPTS.parents[0]
    / "crates"
    / "sekai-harness"
    / "src"
    / "relational_snapshot.rs"
)
PIN = "ghcr.io/sannrox/keiko:v0.1.0"


def script_text():
    return SCRIPT.read_text()


class KeikoRelationalRehearsal(unittest.TestCase):
    def test_script_parses(self):
        subprocess.run(["bash", "-n", str(SCRIPT)], check=True)

    def test_pins_the_published_fixture_image(self):
        text = script_text()
        self.assertIn(f"KEIKO_IMAGE:-{PIN}", text)
        rust = DRIVER.read_text()
        self.assertIn(f'"{PIN}"', rust)
        self.assertNotRegex(text, r"^\s*build:", re.M)

    def test_compose_is_generated_from_the_image(self):
        text = script_text()
        self.assertIn("compose.yaml", text)
        self.assertIn("up -d --wait", text)
        self.assertNotIn("--build", text)
        self.assertIn("COMPOSE_PROJECT_NAME", text)
        self.assertIn('PROJECT="keiko-r$$"', text)
        self.assertIn("down -v", text)
        self.assertIn("cp keiko:/app/tls/ca.crt", text)

    def test_plane_and_runtime_are_isolated(self):
        text = script_text()
        self.assertIn('OPS_PORT=""', text)
        self.assertIn('SEKAI_HTTP_PORT=""', text)
        self.assertIn("SEKAI_EXPERIMENTAL_RPCS=1", text)
        self.assertIn("SEKAI_INSECURE=1", text)
        self.assertIn("free_port", text)
        self.assertIn("sekai-connector-runtime", text)
        self.assertIn("relational-snapshot-rehearsal", text)

    def test_driver_receives_the_edge_flags(self):
        text = script_text()
        for flag in (
            "--plane",
            "--keiko",
            "--keiko-ca",
            "--db-endpoint",
            "--out",
        ):
            self.assertIn(flag, text)
        self.assertIn("ops/keiko-connector", text)
        self.assertIn("role", text)
        self.assertIn("rehearsal", text)
        self.assertIn("KEIKO_CONNECTOR_PASSWORD", text)
