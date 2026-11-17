#!/usr/bin/env python3
"""Write a CycloneDX 1.5 SBOM from `cargo metadata` (locked workspace)."""

from __future__ import annotations

import json
import re
import subprocess
import sys
import uuid
from pathlib import Path

ROOT_NAME = "sekai-chisei"
# SPDX license identifiers are tokens; expressions use OR/AND/WITH or spaces.
SPDX_ID = re.compile(r"^[A-Za-z0-9.+-]+$")


def cargo_metadata(root: Path) -> dict:
    raw = subprocess.check_output(
        ["cargo", "metadata", "--locked", "--format-version", "1"],
        cwd=root,
        text=True,
    )
    return json.loads(raw)


def license_item(raw: str) -> dict | None:
    text = (raw or "").strip()
    if not text:
        return None
    if SPDX_ID.fullmatch(text):
        return {"license": {"id": text}}
    return {"expression": text}


def bom_from_metadata(meta: dict) -> dict:
    workspace = set(meta.get("workspace_members") or [])
    packages = meta.get("packages") or []
    root_pkg = None
    components = []
    for pkg in packages:
        pid = pkg.get("id")
        name = pkg.get("name")
        version = pkg.get("version")
        if pid in workspace and name == ROOT_NAME:
            root_pkg = pkg
        purl = f"pkg:cargo/{name}@{version}"
        component = {
            "type": "library",
            "bom-ref": purl,
            "name": name,
            "version": version,
            "purl": purl,
        }
        item = license_item(pkg.get("license") or "")
        if item is not None:
            component["licenses"] = [item]
        if pid not in workspace:
            components.append(component)
    if root_pkg is None:
        raise SystemExit(f"cargo metadata did not include package {ROOT_NAME}")
    root_purl = f"pkg:cargo/{ROOT_NAME}@{root_pkg['version']}"
    bom = {
        "bomFormat": "CycloneDX",
        "specVersion": "1.5",
        "version": 1,
        "metadata": {
            "component": {
                "type": "application",
                "bom-ref": root_purl,
                "name": ROOT_NAME,
                "version": root_pkg["version"],
                "purl": root_purl,
            }
        },
        "components": sorted(components, key=lambda item: item["bom-ref"]),
    }

    document = json.dumps(bom, sort_keys=True, separators=(",", ":"))
    bom["serialNumber"] = uuid.uuid5(uuid.NAMESPACE_URL, document).urn
    return bom


def main(argv: list[str]) -> None:
    if len(argv) != 1:
        raise SystemExit("usage: sbom.py OUT")
    root = Path(__file__).resolve().parents[2]
    bom = bom_from_metadata(cargo_metadata(root))
    out = Path(argv[0])
    out.write_text(json.dumps(bom, indent=2) + "\n")
    print(out)


if __name__ == "__main__":
    main(sys.argv[1:])
