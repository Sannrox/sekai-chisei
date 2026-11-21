"""n1-upgrade fail dumps print the step that failed, not leftover $detail (#2851).

governed/verify_receipt write .run/.attest-* files, and mixed read-back writes
mixed-cur.expand, but the fail sites used $detail or mixed-n1.expand.
"""

import os
import pathlib
import subprocess
import tempfile
import unittest

SCRIPT = pathlib.Path(
    os.environ.get(
        "N1_UPGRADE_SCRIPT",
        pathlib.Path(__file__).resolve().parents[1] / "n1-upgrade.sh",
    )
)

CHECKS = (
    "mixed window: each server reads the other's writes",
    "mixed window: governed operations on both servers",
    "current server writes on the upgraded store",
    "wire: N-1 sekaictl writes to the current server",
)


def _extract_fn(src: str, name: str) -> str:
    marker = f"{name}() {{"
    start = src.index(marker)
    depth = 0
    for i, ch in enumerate(src[start:], start):
        if ch == "{":
            depth += 1
        elif ch == "}":
            depth -= 1
            if depth == 0:
                return src[start : i + 1]
    raise AssertionError(f"unclosed {name}")


def _extract_fail_site(src: str, check: str) -> str:
    lines = src.splitlines()
    fail_idx = next(
        i for i, line in enumerate(lines) if "fail " in line and check in line
    )
    else_idx = fail_idx
    while else_idx >= 0 and lines[else_idx].lstrip() != "else":
        else_idx -= 1
    if else_idx < 0:
        raise AssertionError(f"no else for {check}")
    return "\n".join(lines[else_idx + 1 : fail_idx + 1])


def _reporting(src: str) -> str:
    parts = [_extract_fn(src, "fail")]
    if "detail_cat() {" in src:
        parts.append(_extract_fn(src, "detail_cat"))
    return "\n".join(parts)


class N1UpgradeFailDetail(unittest.TestCase):
    def setUp(self):
        tmp = tempfile.TemporaryDirectory(prefix=f"n1fd{os.getpid()}-")
        self.addCleanup(tmp.cleanup)
        self.dir = pathlib.Path(tmp.name)
        self.src = SCRIPT.read_text()
        (self.dir / "mixed-cur.expand").write_text("CUR-FAIL expand\n")
        (self.dir / "mixed-n1.expand").write_text("STALE n1 expand\n")
        (self.dir / "detail").write_text("STALE leftover detail\n")
        (self.dir / "cur-b.expand").write_text("CUR-B expand\n")
        (self.dir / "cur-c.expand").write_text("CUR-C expand\n")
        for stem in ("mixed-n1-op", "mixed-cur-op", "cur-op", "wire-op"):
            (self.dir / f"{stem}.run").write_text(f"{stem} GOV-FAIL run\n")
            (self.dir / f"{stem}.attest-export").write_text(f"{stem} EXPORT-FAIL\n")
            (self.dir / f"{stem}.attest-verify").write_text(f"{stem} ATTEST-FAIL\n")
        (self.dir / "n1.log").write_text("n1 log\n")
        (self.dir / "cur.log").write_text("cur log\n")

    def dump(self, check: str) -> str:
        driver = self.dir / "driver.sh"
        driver.write_text(
            "\n".join(
                [
                    "#!/usr/bin/env bash",
                    "set -euo pipefail",
                    "FAILURES=0",
                    _reporting(self.src),
                    f'dir={self.dir.as_posix()!r}',
                    "label=test",
                    'n1_log="$dir/n1.log"',
                    'cur_log="$dir/cur.log"',
                    'detail="$dir/detail"',
                    _extract_fail_site(self.src, check),
                ]
            )
            + "\n"
        )
        result = subprocess.run(
            ["bash", str(driver)],
            capture_output=True,
            text=True,
            timeout=10,
        )
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        return result.stdout + result.stderr

    def test_mixed_read_prints_the_failed_expand(self):
        dump = self.dump(CHECKS[0])
        self.assertIn("--- mixed-cur.expand ---", dump)
        self.assertIn("CUR-FAIL expand", dump)
        self.assertNotIn("STALE leftover detail", dump)

    def test_mixed_governed_prints_run_and_attest_files(self):
        dump = self.dump(CHECKS[1])
        self.assertIn("--- mixed-n1-op.run ---", dump)
        self.assertIn("mixed-n1-op GOV-FAIL run", dump)
        self.assertIn("mixed-n1-op EXPORT-FAIL", dump)
        self.assertIn("mixed-n1-op ATTEST-FAIL", dump)
        self.assertIn("mixed-cur-op GOV-FAIL run", dump)
        self.assertNotIn("STALE leftover detail", dump)

    def test_upgraded_store_write_prints_governed_files(self):
        dump = self.dump(CHECKS[2])
        self.assertIn("cur-op GOV-FAIL run", dump)
        self.assertIn("cur-op EXPORT-FAIL", dump)
        self.assertIn("cur-op ATTEST-FAIL", dump)

    def test_wire_write_prints_governed_files(self):
        dump = self.dump(CHECKS[3])
        self.assertIn("wire-op GOV-FAIL run", dump)
        self.assertIn("wire-op EXPORT-FAIL", dump)
        self.assertIn("wire-op ATTEST-FAIL", dump)
