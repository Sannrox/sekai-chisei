"""Tests for scripts/release/, scripts/check-semver.py, and the release workflows."""

import importlib.util
import pathlib

ROOT = pathlib.Path(__file__).resolve().parents[3]
RELEASE = ROOT / "scripts" / "release"


def load(path: pathlib.Path):
    """Import a script by path; scripts are not a package."""
    spec = importlib.util.spec_from_file_location(f"script_{path.stem.replace('-', '_')}", path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def load_release(name: str):
    """Import scripts/release/<name>.py."""
    return load(RELEASE / f"{name}.py")
