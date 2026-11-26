"""Pinned toolchain auto-install includes cargo (#3533)."""

import re
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]


class Toolchain(unittest.TestCase):
    def test_components_include_cargo(self):
        text = (ROOT / "rust-toolchain.toml").read_text()
        match = re.search(r"(?m)^components\s*=\s*\[([^\]]*)\]", text)
        self.assertIsNotNone(match, "rust-toolchain.toml must list components")
        names = [
            part.strip().strip('"')
            for part in match.group(1).split(",")
            if part.strip()
        ]
        self.assertIn("cargo", names)


if __name__ == "__main__":
    unittest.main()
