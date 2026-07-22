import json
import unittest
from pathlib import Path

from sekai_capability import invocation, native_metadata, normalize_error


FIXTURE = json.loads(
    (Path(__file__).parents[2] / "tests/fixtures/capability_projection/v1.json").read_text()
)


class CapabilityConformanceTest(unittest.TestCase):
    def capability(self):
        return {
            **FIXTURE["capability"],
            "projection_version": FIXTURE["projection_version"],
            "context": FIXTURE["context"],
        }

    def test_preserves_authority_correlation_and_errors(self):
        call = invocation(
            self.capability(),
            FIXTURE["invocation"]["operation_id"],
            FIXTURE["invocation"]["input"],
        )
        self.assertEqual(native_metadata(call), FIXTURE["expected_metadata"])
        self.assertEqual(
            normalize_error(call, "permission_denied", "write denied"),
            FIXTURE["expected_error"],
        )

    def test_fails_closed_on_contract_drift(self):
        capability = self.capability()
        capability["maximum_compatible_version"] = "2.0"
        with self.assertRaisesRegex(ValueError, "version drift"):
            invocation(capability, "operation-1", {})


if __name__ == "__main__":
    unittest.main()
