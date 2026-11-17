"""notes.py: GitHub Release notes are exactly one CHANGELOG section."""

import unittest

from tests.release import load_release

notes = load_release("notes")

SAMPLE = (
    "# Changelog\n\n"
    "## [Unreleased]\n\n"
    "- pending\n\n"
    "## [0.2.0] - 2026-10-30\n\n"
    "### Added\n\n"
    "- release workflow\n\n"
    "## [0.1.0] - 2026-10-12\n\n"
    "First tagged release.\n"
)


class Notes(unittest.TestCase):
    def test_takes_only_the_versions_section(self):
        body = notes.notes_for(SAMPLE, "0.2.0")
        self.assertIn("release workflow", body)
        self.assertNotIn("First tagged release", body)
        self.assertTrue(notes.notes_for(SAMPLE, "0.1.0").startswith("First tagged release"))

    def test_reads_unbracketed_headings(self):
        text = (
            "# Changelog\n\n## Unreleased\n\n## 1.4.0\n\nUpgrade notes:\n\n"
            "- Community SQLite (`GATE:mig`).\n\n## 1.3.0\n\nOlder notes.\n"
        )
        body = notes.notes_for(text, "1.4.0")
        self.assertIn("GATE:mig", body)
        self.assertNotIn("Older notes", body)

    def test_refuses_a_missing_section(self):
        with self.assertRaisesRegex(SystemExit, r"no ## \[9\.9\.9\] or ## 9\.9\.9 section"):
            notes.notes_for(SAMPLE, "9.9.9")

    def test_refuses_an_empty_section(self):
        with self.assertRaisesRegex(SystemExit, "empty CHANGELOG section"):
            notes.notes_for("# Changelog\n\n## [0.1.0]\n\n", "0.1.0")

    def test_a_final_release_never_reuses_its_prerelease_section(self):
        text = "# Changelog\n\n## [1.5.0-rc.1] - 2026-11-01\n\n- candidate\n\n## 1.4.0\n\nOlder notes.\n"
        self.assertEqual(notes.notes_for(text, "1.5.0-rc.1"), "- candidate")
        with self.assertRaisesRegex(SystemExit, r"no ## \[1\.5\.0\] or ## 1\.5\.0 section"):
            notes.notes_for(text, "1.5.0")


if __name__ == "__main__":
    unittest.main()
