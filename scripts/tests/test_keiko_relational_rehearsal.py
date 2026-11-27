"""The relational snapshot rehearsal starts a pinned fixture image (#2358).

The command must pin ghcr.io/sannrox/keiko:v0.1.0, extract compose from that
image with no build, isolate the plane on unique ports, compare, advance,
then repeat at medium size while sampling connector RSS. It never vendors
the fixture into this repository.
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

    def test_starts_from_the_image_compose_never_a_checkout(self):
        text = script_text()
        self.assertIn('run --rm --entrypoint cat "$KEIKO_IMAGE" compose.yaml', text)
        self.assertIn("up -d --wait --no-build", text)
        self.assertNotRegex(text, r"(^|\s)--build(\s|$)")
        self.assertIn("COMPOSE_PROJECT_NAME", text)
        self.assertIn('PROJECT="keiko-r$$"', text)
        self.assertIn("down -v", text)
        self.assertIn("cp keiko:/app/tls/ca.crt", text)
        self.assertIn('pull "$KEIKO_IMAGE"', text)
        self.assertIn("failed to pull", text)

    def test_plane_and_runtime_are_isolated(self):
        text = script_text()
        self.assertIn('OPS_PORT=""', text)
        self.assertIn('SEKAI_HTTP_PORT=""', text)
        self.assertIn("SEKAI_EXPERIMENTAL_RPCS=1", text)
        self.assertIn("SEKAI_INSECURE=1", text)
        self.assertIn("free_port", text)
        self.assertIn("cargo build --locked --bin sekai-chisei", text)
        self.assertIn("cargo build --locked -p sekai-connector-runtime --bin sekai-connector-runtime", text)
        self.assertIn("cargo build --locked -p sekai-harness --bin relational-snapshot-rehearsal", text)
        self.assertIn('CARGO_TARGET_DIR="$ROOT/target"', text)
        self.assertIn('mktemp -d /tmp/krr-XXXXXX', text)
        self.assertIn("exited before", text)
        self.assertIn("wait_for_tcp", text)
        self.assertIn("wait_for_tls", text)
        self.assertIn("wait_for_postgres_tls", text)
        self.assertIn("80877103", text)
        self.assertIn("--ensure-only", text)
        self.assertIn("sekai-connector-runtime: registered", text)

    def test_driver_receives_the_edge_flags(self):
        text = script_text()
        for flag in (
            "--plane",
            "--keiko",
            "--keiko-ca",
            "--db-endpoint",
            "--out",
            "--run-name",
            "--advance-steps",
        ):
            self.assertIn(flag, text)
        self.assertIn("ops/keiko-connector", text)
        self.assertIn("role", text)
        self.assertIn("rehearsal", text)
        self.assertIn("KEIKO_CONNECTOR_PASSWORD", text)
        self.assertIn('https://localhost:${KEIKO_PORT}', text)
        self.assertIn('"localhost:${KEIKO_DB_PORT}"', text)

    def test_small_then_medium_records_connector_resources(self):
        text = script_text()
        self.assertIn("run_pass small initial 20", text)
        self.assertIn("run_pass medium medium 0", text)
        self.assertIn("KEIKO_RELATIONAL_REHEARSAL_SKIP_SMALL", text)
        self.assertIn("sample_rss", text)
        self.assertIn("peak_rss_kb", text)
        self.assertIn("wall_ms", text)
        self.assertIn("KEIKO_SIZE", text)
        rust = DRIVER.read_text()
        self.assertIn("hard_delete_observation", rust)
        self.assertIn("HARD_DELETE_EVERY", rust)
