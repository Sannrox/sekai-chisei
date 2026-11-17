"""manifest.py and record.py: the family manifest never names a latest image."""

import json
import os
import pathlib
import tempfile
import unittest

from tests.release import load_release

manifest = load_release("manifest")
record = load_release("record")


def build(dist: pathlib.Path, **overrides) -> dict:
    args = dict(
        component=manifest.COMPONENT, version="1.4.0", git_sha="a" * 40, tag="v1.4.0",
        dist=dist, images=[], attestations=[], gate_flags=[],
    )
    return manifest.build_manifest(**{**args, **overrides})


class Manifest(unittest.TestCase):
    def setUp(self):
        tmp = tempfile.TemporaryDirectory(prefix=f"mf{os.getpid()}-")
        self.addCleanup(tmp.cleanup)
        self.dist = pathlib.Path(tmp.name)

    def test_gate_flags_come_from_risk_and_gate_labels(self):
        labels = ["risk:breaking", "area:ops", "GATE:mig", "risk:realm", "docs"]
        self.assertEqual(manifest.gate_flags_from_labels(labels), ["breaking", "migration", "realm"])
        self.assertEqual(manifest.gate_flags_from_labels([]), [])

    def test_refuses_a_short_git_sha(self):
        with self.assertRaises(SystemExit):
            build(self.dist, git_sha="deadbeef")

    def test_refuses_a_latest_image(self):
        with self.assertRaisesRegex(SystemExit, "latest"):
            manifest.parse_image("sekai-chisei:latest=sha256:" + "a" * 64)

    def test_lists_binaries_with_digests_and_skips_checksums_and_image_tarballs(self):
        (self.dist / "sekai-1.4.0-x86_64-unknown-linux-gnu.tar.gz").write_bytes(b"bin")
        (self.dist / "sekai-chisei-1.4.0-image.tar").write_bytes(b"tar")
        (self.dist / "SHA256SUMS").write_text("skip\n")
        image = {"name": "ghcr.io/example/sekai-chisei:v1.4.0", "digest": "sha256:" + "b" * 64}
        got = build(self.dist, images=[image], gate_flags=["breaking"])
        self.assertEqual(got["schema"], "tenkai.family-release-manifest.v1")
        [binary] = got["binaries"]
        self.assertEqual(binary["name"], "sekai-1.4.0-x86_64-unknown-linux-gnu.tar.gz")
        self.assertTrue(binary["digest"].startswith("sha256:"))
        self.assertEqual(got["images"], [image])
        self.assertNotIn("latest", json.dumps(got))


class Record(unittest.TestCase):
    BASE = {"schema": "tenkai.family-release-manifest.v1", "images": [], "attestations": []}

    def test_attestations_drop_empty_urls(self):
        got = record.with_attestations(self.BASE, ["https://example.invalid/a", ""])
        self.assertEqual(got["attestations"], ["https://example.invalid/a"])

    def test_image_sets_the_one_published_image(self):
        got = record.with_image(self.BASE, "ghcr.io/example/sekai-chisei:v1.4.0", "sha256:" + "c" * 64)
        self.assertEqual(got["images"], [{"name": "ghcr.io/example/sekai-chisei:v1.4.0", "digest": "sha256:" + "c" * 64}])

    def test_image_refuses_latest_and_a_non_sha256_digest(self):
        for name, digest in (
            ("ghcr.io/example/sekai-chisei:latest", "sha256:" + "c" * 64),
            ("ghcr.io/example/sekai-chisei:v1.4.0", "md5:abc"),
            ("ghcr.io/example/latest:v1.4.0", "sha256:" + "c" * 64),
        ):
            with self.subTest(name=name, digest=digest), self.assertRaises(SystemExit):
                record.with_image(self.BASE, name, digest)


if __name__ == "__main__":
    unittest.main()
