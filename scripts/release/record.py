#!/usr/bin/env python3
"""Record release facts on the family manifest after it was packaged.

    python3 scripts/release/record.py image MANIFEST NAME DIGEST

``image`` upserts one published image by name; it refuses a ``latest`` tag or a
digest that is not ``sha256:``. The manifest's ``attestations`` list stays
empty: the release attests the final manifest and SHA256SUMS after this last
patch, so no attestation URL can be recorded inside them. Verify by digest
with ``gh attestation verify``.
"""

from __future__ import annotations

import json
import pathlib
import sys


def load(path: pathlib.Path) -> dict:
    return json.loads(path.read_text())


def dump(path: pathlib.Path, manifest: dict) -> None:
    path.write_text(json.dumps(manifest, indent=2, sort_keys=True) + "\n")


def with_image(manifest: dict, name: str, digest: str) -> dict:
    if name.rsplit(":", 1)[-1] == "latest":
        raise SystemExit("images must not use a latest tag")
    if not digest.startswith("sha256:"):
        raise SystemExit("image digest must be sha256:...")
    images = [image for image in manifest.get("images", []) if image.get("name") != name]
    images.append({"name": name, "digest": digest})
    images.sort(key=lambda image: image["name"])
    patched = {**manifest, "images": images}
    if "latest" in json.dumps(patched):
        raise SystemExit("manifest must not mention latest")
    return patched


def main(argv: list[str]) -> None:
    if len(argv) == 4 and argv[0] == "image":
        path = pathlib.Path(argv[1])
        dump(path, with_image(load(path), argv[2], argv[3]))
        print(f"image {argv[2]} digest {argv[3]}")
    else:
        raise SystemExit("usage: record.py image MANIFEST NAME DIGEST")


if __name__ == "__main__":
    main(sys.argv[1:])
