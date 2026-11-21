"""n1-upgrade stops when a revision has no server, no CLI, or no package name (#2811).

server_bin_name is only called from $(...), where bash ignores errexit inside
the function. A failed git show or an empty awk name must still exit the script.
"""

import os
import pathlib
import shutil
import subprocess
import tempfile
import unittest

SCRIPT = pathlib.Path(__file__).resolve().parents[1] / "n1-upgrade.sh"
MANIFEST = '[package]\nname = "demo"\nversion = "1.0.0"\n'
MANIFEST_NO_NAME = '[package]\nversion = "1.0.0"\n'


class ServerBinName(unittest.TestCase):
    def setUp(self):
        tmp = tempfile.TemporaryDirectory(prefix=f"n1sb{os.getpid()}-")
        self.addCleanup(tmp.cleanup)
        self.work = pathlib.Path(tmp.name)
        self.scripts = self.work / "scripts"
        self.scripts.mkdir()
        shutil.copy(SCRIPT, self.scripts / "n1-upgrade.sh")
        self.git("init", "-q", "-b", "main")
        self.git("config", "user.name", "n1-upgrade")
        self.git("config", "user.email", "n1-upgrade@example.invalid")
        self.git("config", "commit.gpgsign", "false")
        self.git("config", "tag.gpgSign", "false")

    def git(self, *args):
        subprocess.run(["git", "-C", str(self.work), *args], check=True, capture_output=True)

    def commit_tree(self, *, manifest, main=True, sekaictl="bin", message="commit"):
        cargo = self.work / "Cargo.toml"
        cargo.write_text(manifest)
        main_path = self.work / "src" / "main.rs"
        bin_path = self.work / "src" / "bin" / "sekaictl.rs"
        crate_path = self.work / "crates" / "sekaictl" / "src" / "main.rs"
        if main_path.exists():
            main_path.unlink()
        if bin_path.exists():
            bin_path.unlink()
        if crate_path.exists():
            crate_path.unlink()
        if main:
            main_path.parent.mkdir(parents=True, exist_ok=True)
            main_path.write_text("fn main() {}\n")
        if sekaictl == "bin":
            bin_path.parent.mkdir(parents=True, exist_ok=True)
            bin_path.write_text("fn main() {}\n")
        elif sekaictl == "crate":
            crate_path.parent.mkdir(parents=True, exist_ok=True)
            crate_path.write_text("fn main() {}\n")
        self.git("add", "-A")
        self.git("commit", "-q", "-m", message)

    def run_script(self, n1_tag="v1.0.0"):
        env = {
            **os.environ,
            "N1_TAG": n1_tag,
            "CARGO_TARGET_DIR": str(self.work / "target"),
        }
        return subprocess.run(
            ["bash", str(self.scripts / "n1-upgrade.sh")],
            cwd=self.work,
            env=env,
            capture_output=True,
            text=True,
            timeout=20,
        )

    def tag_n1_then_head(self, **n1):
        self.commit_tree(message="n1", **n1)
        self.git("tag", "v1.0.0")
        self.commit_tree(
            manifest=MANIFEST, main=True, sekaictl="bin", message="head"
        )

    def test_missing_main_exits_and_names_the_revision(self):
        self.tag_n1_then_head(manifest=MANIFEST, main=False, sekaictl="bin")
        result = self.run_script()
        self.assertNotEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertRegex(result.stderr, r"v1\.0\.0|refs/tags/v1\.0\.0")

    def test_missing_sekaictl_exits_and_names_the_revision(self):
        self.tag_n1_then_head(manifest=MANIFEST, main=True, sekaictl=None)
        result = self.run_script()
        self.assertNotEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertRegex(result.stderr, r"v1\.0\.0|refs/tags/v1\.0\.0")

    def test_empty_package_name_exits_before_building(self):
        self.tag_n1_then_head(manifest=MANIFEST_NO_NAME, main=True, sekaictl="bin")
        result = self.run_script()
        self.assertNotEqual(result.returncode, 0, result.stdout + result.stderr)
        combined = result.stdout + result.stderr
        self.assertRegex(combined, r"v1\.0\.0|refs/tags/v1\.0\.0")
        self.assertNotIn("building", combined)
