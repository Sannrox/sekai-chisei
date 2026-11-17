#!/usr/bin/env python3
"""Public-API gates for pull requests and release prep.

Pull requests: cargo-semver-checks against the PR base only, plus a lint that
new public enums carry ``#[non_exhaustive]``. A reported major vs the base
passes only with the breaking waiver. Versions are release-owned: release mode
owns the comparison against the last final v* tag, so pull requests do not
repeat it.

Release prep: cargo-semver-checks against the previous final v* tag. A major
fails when the crate version did not major. No waiver at release time.

    python3 scripts/check-semver.py pr
    python3 scripts/check-semver.py release

Unit tests: scripts/tests/release/test_check_semver.py.
"""

from __future__ import annotations

import json
import os
import pathlib
import re
import subprocess
import sys

ROOT = pathlib.Path(__file__).resolve().parent.parent
BANG_TITLE = re.compile(r"^[a-z]+(\([^)]*\))?!:")
MARKED_BODY = re.compile(r"^(BREAKING[ -]CHANGE|#+ *(Breaking|Upgrade))", re.M)
PACKAGE_VERSION = re.compile(
    r'(?ms)^\[package\][^\[]*?^version\s*=\s*"([^"]+)"'
)
ATTR_LINE = re.compile(r"^[ \t]*#\[(?P<body>[^\]]*)\]")
PUB_ENUM = re.compile(r"^[ \t]*pub enum\s+(?P<name>\w+)")
KEEP_ATTRS = re.compile(r"^[ \t]*(///|//!|//[^!/]|$)")


def fail(message: str) -> None:
    print(f"check-semver: {message}", file=sys.stderr)
    raise SystemExit(1)


def notice(message: str) -> None:
    print(f"::notice::{message}")


def error(message: str) -> None:
    print(f"::error::{message}")


def last_final_tag(rev: str) -> str | None:
    proc = subprocess.run(
        [
            "git",
            "describe",
            "--tags",
            "--abbrev=0",
            "--match",
            "v*",
            "--exclude",
            "*-*",
            rev,
        ],
        cwd=ROOT,
        capture_output=True,
        text=True,
    )
    tag = proc.stdout.strip()
    return tag or None


def breaking_waiver(title: str, body: str, labels: list[str]) -> bool:
    marked = bool(BANG_TITLE.match(title)) or bool(MARKED_BODY.search(body or ""))
    return marked and "risk:breaking" in labels


def classify_semver_output(out: str, rc: int) -> str:
    if rc == 0:
        return "ok"
    if "semver requires new major version" in out:
        return "major"
    if "semver requires new minor version" in out:
        return "minor"
    return "error"


def crate_major(version: str) -> int:
    head = version.lstrip("v").split(".", 1)[0]
    if not head.isdigit():
        fail(f"not a semver major: {version}")
    return int(head)


def major_bumped(head_version: str, tag_version: str) -> bool:
    return crate_major(head_version) > crate_major(tag_version)


def toml_package_version(text: str) -> str:
    match = PACKAGE_VERSION.search(text)
    if match is None:
        fail("Cargo.toml has no [package] version")
    return match.group(1)


def public_enums(text: str) -> list[tuple[str, bool]]:
    """Return ``(name, has_non_exhaustive)`` for each ``pub enum`` in *text*."""
    pending: list[str] = []
    found: list[tuple[str, bool]] = []
    for raw in text.splitlines():
        while True:
            attr = ATTR_LINE.match(raw)
            if attr is None:
                break
            pending.append(attr.group("body").strip())
            raw = raw[attr.end() :]
        if KEEP_ATTRS.match(raw) is not None:
            continue
        enum = PUB_ENUM.match(raw)
        if enum is not None:
            has = any(body == "non_exhaustive" for body in pending)
            found.append((enum.group("name"), has))
        pending = []
    return found


def new_enums_missing_non_exhaustive(
    base: dict[tuple[str, str], bool],
    head: dict[tuple[str, str], bool],
) -> list[str]:
    missing: list[str] = []
    for key, has in sorted(head.items()):
        if key not in base and not has:
            missing.append(f"{key[0]}::{key[1]}")
    return missing


def evaluate_pr(
    vs_base: dict[str, str],
    waived: bool,
    missing_enums: list[str],
) -> int:
    """Return the process exit code; print GitHub annotations."""
    errors = sorted(name for name, kind in vs_base.items() if kind == "error")
    if errors:
        error(
            "cargo-semver-checks failed without reporting an API break for: "
            + ", ".join(errors)
            + "; see the log."
        )
        return 1
    introduced = sorted(
        name for name, kind in vs_base.items() if kind == "major"
    )
    for name, kind in sorted(vs_base.items()):
        if kind == "minor":
            notice(f"{name}: minor-level API change vs the pull request base (compatible).")
    failed = False
    if introduced:
        print("API break reported in: " + " ".join(introduced))
        if waived:
            notice(
                "Public API break accepted: the pull request is marked breaking "
                "and labelled risk:breaking."
            )
        else:
            error(
                "cargo-semver-checks found a public API break. Mark the pull "
                "request breaking (a 'type!:' title or a '### Breaking' heading) "
                "and add the risk:breaking label, or keep the change compatible."
            )
            failed = True
    if missing_enums:
        error(
            "new public enum missing #[non_exhaustive]: " + ", ".join(missing_enums)
        )
        failed = True
    return 1 if failed else 0


def evaluate_release(
    vs_tag: dict[str, str],
    versions: dict[str, tuple[str, str]],
    tag: str,
) -> int:
    errors = sorted(name for name, kind in vs_tag.items() if kind == "error")
    if errors:
        error(
            "cargo-semver-checks failed without reporting an API break for: "
            + ", ".join(errors)
            + "; see the log."
        )
        return 1
    stuck = []
    for name, kind in sorted(vs_tag.items()):
        if kind != "major":
            continue
        head_ver, tag_ver = versions[name]
        if major_bumped(head_ver, tag_ver):
            notice(
                f"{name}: public API vs {tag} requires a new major; "
                f"crate version {head_ver} already majored from {tag_ver}."
            )
            continue
        stuck.append(f"{name} {head_ver} (tag {tag} was {tag_ver})")
    if not stuck:
        return 0
    error(
        "cargo-semver-checks vs "
        + tag
        + " requires a new major version, but the crate version did not major: "
        + "; ".join(stuck)
    )
    return 1


def library_packages(metadata: dict, root: pathlib.Path) -> list[tuple[str, str, str]]:
    """Return ``(name, relative manifest, relative lib src dir)``."""
    packages: list[tuple[str, str, str]] = []
    root_s = str(root) + os.sep
    for package in metadata["packages"]:
        lib = next(
            (t for t in package["targets"] if "lib" in t.get("kind", [])),
            None,
        )
        if lib is None:
            continue
        manifest = package["manifest_path"]
        if manifest.startswith(root_s):
            manifest = manifest[len(root_s) :]
        src = pathlib.Path(lib["src_path"])
        src_dir = src.parent
        rel_src = str(src_dir)
        if rel_src.startswith(root_s):
            rel_src = rel_src[len(root_s) :]
        packages.append((package["name"], manifest, rel_src))
    return packages


def git_show(rev: str, path: str) -> str | None:
    proc = subprocess.run(
        ["git", "show", f"{rev}:{path}"],
        cwd=ROOT,
        capture_output=True,
        text=True,
    )
    if proc.returncode != 0:
        return None
    return proc.stdout


def git_exists(rev: str, path: str) -> bool:
    proc = subprocess.run(
        ["git", "cat-file", "-e", f"{rev}:{path}"],
        cwd=ROOT,
        capture_output=True,
        text=True,
    )
    return proc.returncode == 0


def iter_rs_files(src_dir: pathlib.Path) -> list[pathlib.Path]:
    if not src_dir.is_dir():
        return []
    skip = {"bin", "tests", "examples", "benches"}
    files: list[pathlib.Path] = []
    for path in src_dir.rglob("*.rs"):
        rel = path.relative_to(src_dir)
        if any(part in skip for part in rel.parts):
            continue
        files.append(path)
    return files


def enums_in_tree(src_dir: pathlib.Path, root: pathlib.Path) -> dict[tuple[str, str], bool]:
    found: dict[tuple[str, str], bool] = {}
    for path in iter_rs_files(src_dir):
        rel = str(path.relative_to(root))
        for name, has in public_enums(path.read_text()):
            found[(rel, name)] = has
    return found


def enums_at_rev(rev: str, files: list[str]) -> dict[tuple[str, str], bool]:
    found: dict[tuple[str, str], bool] = {}
    for rel in files:
        text = git_show(rev, rel)
        if text is None:
            continue
        for name, has in public_enums(text):
            found[(rel, name)] = has
    return found


def cargo_metadata() -> dict:
    proc = subprocess.run(
        ["cargo", "metadata", "--locked", "--no-deps", "--format-version", "1"],
        cwd=ROOT,
        capture_output=True,
        text=True,
    )
    if proc.returncode != 0:
        sys.stderr.write(proc.stderr)
        fail("cargo metadata failed")
    return json.loads(proc.stdout)


def run_semver_checks(package: str, baseline_rev: str) -> tuple[int, str]:
    proc = subprocess.run(
        [
            "cargo",
            "semver-checks",
            "--package",
            package,
            "--baseline-rev",
            baseline_rev,
        ],
        cwd=ROOT,
        capture_output=True,
        text=True,
    )
    out = proc.stdout + proc.stderr
    print(out, end="" if out.endswith("\n") or not out else "\n")
    return proc.returncode, out


def load_pr(pr: str, repo: str) -> tuple[str, str, list[str]]:
    proc = subprocess.run(
        ["gh", "pr", "view", pr, "--repo", repo, "--json", "title,body,labels"],
        capture_output=True,
        text=True,
    )
    if proc.returncode != 0:
        sys.stderr.write(proc.stderr)
        fail("could not read the pull request")
    data = json.loads(proc.stdout)
    labels = [item["name"] for item in data.get("labels") or []]
    return data.get("title") or "", data.get("body") or "", labels


def classify_package(package: str, baseline: str) -> str:
    rc, out = run_semver_checks(package, baseline)
    kind = classify_semver_output(out, rc)
    if kind == "error":
        error(
            f"cargo-semver-checks failed for {package} without reporting an API break; see the log."
        )
    return kind


def run_pr() -> int:
    base = os.environ.get("BASE") or ""
    pr = os.environ.get("PR") or ""
    repo = os.environ.get("GITHUB_REPOSITORY") or ""
    if not base or not pr:
        fail("pr mode needs BASE and PR")
    metadata = cargo_metadata()
    packages = library_packages(metadata, ROOT)
    vs_base: dict[str, str] = {}
    src_dirs: list[pathlib.Path] = []
    rel_files: list[str] = []
    for name, manifest, src in packages:
        src_dir = ROOT / src
        src_dirs.append(src_dir)
        rel_files.extend(str(p.relative_to(ROOT)) for p in iter_rs_files(src_dir))
        if not git_exists(base, manifest):
            notice(f"{name} is new in this pull request; no baseline to check.")
            continue
        vs_base[name] = classify_package(name, base)
        if vs_base[name] == "error":
            return 1
    head_enums: dict[tuple[str, str], bool] = {}
    for src_dir in src_dirs:
        head_enums.update(enums_in_tree(src_dir, ROOT))
    base_enums = enums_at_rev(base, rel_files)
    missing = new_enums_missing_non_exhaustive(base_enums, head_enums)
    title, body, labels = load_pr(pr, repo)
    waived = breaking_waiver(title, body, labels)
    return evaluate_pr(vs_base, waived, missing)


def run_release() -> int:
    # HEAD may already carry this release's tag; start from the parent so the
    # previous final v* tag is the baseline (same trick as scripts/release/package.sh).
    describe_rev = os.environ.get("CHECK_SEMVER_TAG_REV") or "HEAD^"
    tag = last_final_tag(describe_rev)
    if tag is None:
        notice("No previous final v* tag; nothing to compare against.")
        return 0
    metadata = cargo_metadata()
    packages = library_packages(metadata, ROOT)
    vs_tag: dict[str, str] = {}
    versions: dict[str, tuple[str, str]] = {}
    for name, manifest, _src in packages:
        if not git_exists(tag, manifest):
            notice(f"{name} did not exist at {tag}; no baseline to check.")
            continue
        head_toml = (ROOT / manifest).read_text()
        tag_toml = git_show(tag, manifest)
        if tag_toml is None:
            notice(f"{name} did not exist at {tag}; no baseline to check.")
            continue
        vs_tag[name] = classify_package(name, tag)
        if vs_tag[name] == "error":
            return 1
        versions[name] = (
            toml_package_version(head_toml),
            toml_package_version(tag_toml),
        )
    return evaluate_release(vs_tag, versions, tag)


def main(argv: list[str]) -> None:
    if argv == ["pr"]:
        raise SystemExit(run_pr())
    if argv == ["release"]:
        raise SystemExit(run_release())
    raise SystemExit("usage: check-semver.py {pr|release}")


if __name__ == "__main__":
    main(sys.argv[1:])
