#!/usr/bin/env python3
"""Print the CHANGELOG.md body for one version heading (Keep a Changelog)."""

from __future__ import annotations

import pathlib
import re
import sys


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


def main(argv: list[str]) -> None:
    if len(argv) != 1:
        raise SystemExit("usage: notes.py VERSION")
    version = argv[0]
    text = pathlib.Path("CHANGELOG.md").read_text()
    print(notes_for(text, version))


if __name__ == "__main__":
    main(sys.argv[1:])
