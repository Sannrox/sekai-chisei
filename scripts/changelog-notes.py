#!/usr/bin/env python3
"""Print the CHANGELOG.md body for one version heading (Keep a Changelog)."""

from __future__ import annotations

import pathlib
import re
import sys
import tempfile


def notes_for(text: str, version: str) -> str:
    """Return the section body for `version`.

    Accepts Keep a Changelog ``## [version]`` headings and the unbracketed
    ``## version`` headings this changelog already uses.
    """
    escaped = re.escape(version)
    patterns = (
        rf"^## \[{escaped}\][^\n]*\n",
        rf"^## {escaped}(?:[ \t][^\n]*)?\n",
    )
    for pattern in patterns:
        match = re.search(pattern, text, re.M)
        if match is None:
            continue
        nxt = re.search(r"^## ", text[match.end() :], re.M)
        end = match.end() + nxt.start() if nxt else len(text)
        body = text[match.end() : end].strip()
        if not body:
            raise SystemExit(f"empty CHANGELOG section for {version}")
        return body
    raise SystemExit(f"CHANGELOG.md has no ## [{version}] or ## {version} section")


def self_test() -> None:
    sample = (
        "# Changelog\n\n"
        "## [Unreleased]\n\n"
        "- pending\n\n"
        "## [0.2.0] - 2026-10-30\n\n"
        "### Added\n\n"
        "- release workflow\n\n"
        "## [0.1.0] - 2026-10-12\n\n"
        "First tagged release.\n"
    )
    body = notes_for(sample, "0.2.0")
    assert "release workflow" in body, body
    assert "First tagged release" not in body, body
    try:
        notes_for(sample, "9.9.9")
    except SystemExit as exc:
        assert "no ## [9.9.9] or ## 9.9.9 section" in str(exc)
    else:
        raise SystemExit("expected missing-section failure")
    empty = "# Changelog\n\n## [0.1.0]\n\n"
    try:
        notes_for(empty, "0.1.0")
    except SystemExit as exc:
        assert "empty CHANGELOG section" in str(exc)
    else:
        raise SystemExit("expected empty-section failure")
    unbracketed = (
        "# Changelog\n\n"
        "## Unreleased\n\n"
        "## 1.4.0\n\n"
        "Upgrade notes:\n\n"
        "- Community SQLite (`GATE:mig`).\n\n"
        "## 1.3.0\n\n"
        "Older notes.\n"
    )
    body = notes_for(unbracketed, "1.4.0")
    assert "GATE:mig" in body, body
    assert "Older notes" not in body, body
    with tempfile.TemporaryDirectory() as tmp:
        path = pathlib.Path(tmp) / "CHANGELOG.md"
        path.write_text(sample)
        got = notes_for(path.read_text(), "0.1.0")
        assert got.startswith("First tagged release"), got
    print("changelog-notes self-test passed")


def main(argv: list[str]) -> None:
    if argv == ["--self-test"]:
        self_test()
        return
    if len(argv) != 1:
        raise SystemExit("usage: changelog-notes.py VERSION")
    version = argv[0]
    text = pathlib.Path("CHANGELOG.md").read_text()
    print(notes_for(text, version))


if __name__ == "__main__":
    main(sys.argv[1:])
