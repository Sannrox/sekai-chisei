"""sbom.py: a CycloneDX SBOM whose serial number follows the dependency set."""

import copy
import unittest
import uuid

from tests.release import load_release

sbom = load_release("sbom")

ROOT_ID = f"{sbom.ROOT_NAME} 1.4.0 (path+file:///workspace)"
META = {
    "workspace_members": [ROOT_ID],
    "packages": [
        {"id": ROOT_ID, "name": sbom.ROOT_NAME, "version": "1.4.0", "license": "Apache-2.0"},
        {"id": "libc 0.2.0 (registry+https://github.com/rust-lang/crates.io-index)",
         "name": "libc", "version": "0.2.0", "license": "MIT OR Apache-2.0"},
        {"id": "foo 1.0.0 (registry+https://github.com/rust-lang/crates.io-index)",
         "name": "foo", "version": "1.0.0", "license": "MIT"},
    ],
}


class Sbom(unittest.TestCase):
    def test_describes_the_application(self):
        bom = sbom.bom_from_metadata(META)
        self.assertEqual(bom["bomFormat"], "CycloneDX")
        self.assertEqual(bom["metadata"]["component"]["version"], "1.4.0")
        self.assertEqual(bom["metadata"]["component"]["type"], "application")

    def test_serial_is_a_v5_uuid_that_changes_only_with_the_dependencies(self):
        serial = sbom.bom_from_metadata(META)["serialNumber"]
        self.assertTrue(serial.startswith("urn:uuid:"))
        self.assertEqual(uuid.UUID(serial.removeprefix("urn:uuid:")).version, 5)
        self.assertEqual(sbom.bom_from_metadata(META)["serialNumber"], serial)
        bumped = copy.deepcopy(META)
        bumped["packages"][1]["version"] = "0.2.1"
        self.assertNotEqual(sbom.bom_from_metadata(bumped)["serialNumber"], serial)

    def test_license_expressions_are_not_license_ids(self):
        by_name = {c["name"]: c for c in sbom.bom_from_metadata(META)["components"]}
        self.assertEqual(by_name["libc"]["licenses"], [{"expression": "MIT OR Apache-2.0"}])
        self.assertEqual(by_name["foo"]["licenses"], [{"license": {"id": "MIT"}}])


if __name__ == "__main__":
    unittest.main()
