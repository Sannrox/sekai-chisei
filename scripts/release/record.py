#!/usr/bin/env python3
"""Record release facts on the family manifest after it was packaged.

    python3 scripts/release/record.py attestations MANIFEST [URL...]
    python3 scripts/release/record.py image MANIFEST NAME DIGEST

``attestations`` replaces the manifest's attestation URLs (empty URLs are
dropped). ``image`` sets the one published image; it refuses a ``latest`` tag
or a digest that is not ``sha256:``.
"""

from __future__ import annotations

import json
import pathlib
import sys


def load(path: pathlib.Path) -> dict:
    return json.loads(path.read_text())


def dump(path: pathlib.Path, manifest: dict) -> None:
    path.write_text(json.dumps(manifest, indent=2, sort_keys=True) + "\n")


def with_attestations(manifest: dict, urls: list[str]) -> dict:
    return {**manifest, "attestations": [url for url in urls if url]}


def with_image(manifest: dict, name: str, digest: str) -> dict:
    if name.rsplit(":", 1)[-1] == "latest":
        raise SystemExit("images must not use a latest tag")
    if not digest.startswith("sha256:"):
        raise SystemExit("image digest must be sha256:...")
    patched = {**manifest, "images": [{"name": name, "digest": digest}]}
    if "latest" in json.dumps(patched):
        raise SystemExit("manifest must not mention latest")
    return patched


def main(argv: list[str]) -> None:
    if len(argv) >= 2 and argv[0] == "attestations":
        path = pathlib.Path(argv[1])
        dump(path, with_attestations(load(path), argv[2:]))
    elif len(argv) == 4 and argv[0] == "image":
        path = pathlib.Path(argv[1])
        dump(path, with_image(load(path), argv[2], argv[3]))
        print(f"image {argv[2]} digest {argv[3]}")
    else:
        raise SystemExit("usage: record.py {attestations MANIFEST [URL...]|image MANIFEST NAME DIGEST}")


if __name__ == "__main__":
    main(sys.argv[1:])
