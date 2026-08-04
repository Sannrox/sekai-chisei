import json
from pathlib import Path
import time
import unittest

from sekai_client import (
    CallContext,
    CallOptions,
    ClientConfig,
    SDK_CONTRACT_VERSION,
    SdkError,
    SekaiChiseiClient,
)
from sekai_grpc import _request_message_name


FIXTURE = json.loads(
    (Path(__file__).parents[2] / "tests/fixtures/sdk_core_loop/v1.json").read_text()
)


class FixtureTransport:
    def __init__(self):
        self.calls = []
        self.fail_next = False

    def unary(self, service, method, request, options):
        self.calls.append((service, method, request, options))
        if self.fail_next:
            self.fail_next = False
            error = RuntimeError("fixture unavailable")
            error.code = "UNAVAILABLE"
            raise error
        if service == "sekai" and method == "CreateSchemaType":
            return {"type": request["type"]}
        if service == "sekai" and method == "CreateObject":
            return {"object": request["object"]}
        if service == "sekai" and method == "CreateLink":
            return {"link": request["link"]}
        if service == "chisei" and method == "PlanExecution":
            return {"plan": FIXTURE["plan"]}
        if service == "chisei" and method == "GetOperationReceipt":
            return FIXTURE["receipt"]
        raise AssertionError(f"unexpected fixture unary {service}.{method}")

    def stream(self, service, method, request, options):
        self.calls.append((service, method, request, options))
        if (service, method) != ("chisei", "ExecutePlanStream"):
            raise AssertionError(f"unexpected fixture stream {service}.{method}")
        return iter(FIXTURE["stream_events"])

    def close(self):
        pass


def sdk(transport):
    return SekaiChiseiClient(
        ClientConfig(
            principal=FIXTURE["principal"],
            token=FIXTURE["token"],
            namespace=FIXTURE["namespace"],
            catalog_version=FIXTURE["catalog_version"],
        ),
        transport,
    )


class CoreLoopSdkTest(unittest.TestCase):
    def test_python_uses_the_canonical_stream_request_message(self):
        self.assertEqual(_request_message_name("chisei", "ExecutePlanStream"), "ExecutePlanRequest")
        self.assertEqual(_request_message_name("chisei", "PlanExecution"), "PlanExecutionRequest")

    def test_python_completes_the_core_loop(self):
        self.assertEqual(SDK_CONTRACT_VERSION, FIXTURE["version"])
        transport = FixtureTransport()
        result = sdk(transport).run_core_loop(
            FIXTURE["namespace"],
            FIXTURE["objects"],
            FIXTURE["execution"],
            schema=FIXTURE["schema"],
            links=FIXTURE["links"],
            operation_id=FIXTURE["operation_id"],
        )
        self.assertEqual(result["operation_id"], FIXTURE["operation_id"])
        self.assertEqual(result["request_id"], FIXTURE["request_id"])
        self.assertEqual(result["plan"]["plan_id"], FIXTURE["plan"]["plan_id"])
        self.assertEqual(result["events"], FIXTURE["stream_events"])
        self.assertEqual(result["receipt"], FIXTURE["receipt"])
        self.assertEqual(
            [f"{service}.{method}" for service, method, _, _ in transport.calls],
            [
                "sekai.CreateSchemaType",
                "sekai.CreateObject",
                "sekai.CreateObject",
                "sekai.CreateLink",
                "chisei.PlanExecution",
                "chisei.ExecutePlanStream",
                "chisei.GetOperationReceipt",
            ],
        )
        capabilities = [
            options.metadata["x-sekai-capability"]
            for _, _, _, options in transport.calls
        ]
        self.assertEqual(
            capabilities,
            [
                "sekai.schema.create",
                "sekai.fact.seed",
                "sekai.fact.seed",
                "sekai.fact.seed",
                "chisei.plan.execute",
                "chisei.plan.execute",
                "chisei.receipt.read",
            ],
        )
        for _, _, _, options in transport.calls:
            for key, value in FIXTURE["expected_base_metadata"].items():
                self.assertEqual(options.metadata[key], value)
            self.assertGreater(options.deadline, time.monotonic())
        receipt_request = transport.calls[-1][2]
        self.assertEqual(receipt_request["operation_id"], FIXTURE["plan"]["plan_id"])
        self.assertEqual(receipt_request["request_id"], "")

    def test_python_retries_opted_in_unary_work(self):
        transport = FixtureTransport()
        transport.fail_next = True
        result = sdk(transport).raw.unary(
            "sekai",
            "CreateObject",
            {"object": FIXTURE["objects"][0]},
            CallOptions(
                context=CallContext(operation_id=FIXTURE["operation_id"]),
                retryable=True,
            ),
        )
        self.assertEqual(result, {"object": FIXTURE["objects"][0]})
        self.assertEqual(len(transport.calls), 2)

    def test_python_preserves_an_explicit_non_retryable_transport_error(self):
        class UnsafeTransport(FixtureTransport):
            def unary(self, service, method, request, options):
                raise SdkError("unavailable", "unsafe to replay", retryable=False)

        with self.assertRaises(SdkError) as raised:
            sdk(UnsafeTransport()).raw.unary(
                "sekai",
                "CreateObject",
                {},
                CallOptions(retryable=True),
            )
        self.assertFalse(raised.exception.retryable)

    def test_python_binds_seeded_facts_to_the_requested_namespace(self):
        transport = FixtureTransport()
        sdk(transport).seed_facts(
            FIXTURE["namespace"],
            [{"id": "unscoped", "kind": "service", "name": "unscoped"}],
        )
        self.assertEqual(transport.calls[0][2]["object"]["namespace"], FIXTURE["namespace"])
        with self.assertRaises(SdkError):
            sdk(FixtureTransport()).seed_facts(
                FIXTURE["namespace"],
                [{"id": "foreign", "kind": "service", "name": "foreign", "namespace": "other"}],
            )

    def test_python_receipt_retry_can_be_disabled_explicitly(self):
        transport = FixtureTransport()
        transport.fail_next = True
        with self.assertRaises(SdkError) as raised:
            sdk(transport).get_operation_receipt(
                operation_id=FIXTURE["plan"]["plan_id"],
                options=CallOptions(retryable=False),
            )
        self.assertEqual(raised.exception.code, "unavailable")
        self.assertEqual(len(transport.calls), 1)

    def test_python_maps_authorization_and_protects_reserved_metadata(self):
        class DeniedTransport(FixtureTransport):
            def unary(self, service, method, request, options):
                error = RuntimeError("denied")
                error.code = 7
                raise error

        client = sdk(DeniedTransport())
        with self.assertRaises(SdkError) as raised:
            client.raw.unary("sekai", "GetObject", {})
        self.assertEqual(raised.exception.code, "permission_denied")
        self.assertEqual(str(raised.exception), "RPC permission denied")
        self.assertFalse(raised.exception.retryable)
        with self.assertRaisesRegex(SdkError, "reserved metadata"):
            client.metadata(CallContext(metadata={"authorization": "Bearer attacker"}))

    def test_python_stream_can_be_cancelled(self):
        class CancellableSource:
            def __init__(self):
                self.cancelled = False

            def __iter__(self):
                yield {"content_delta": "never consumed"}

            def cancel(self):
                self.cancelled = True

        class StreamingTransport(FixtureTransport):
            def __init__(self):
                super().__init__()
                self.source = CancellableSource()

            def stream(self, service, method, request, options):
                return self.source

        transport = StreamingTransport()
        stream = sdk(transport).execute_plan_stream(FIXTURE["plan"])
        stream.cancel()
        self.assertTrue(transport.source.cancelled)


if __name__ == "__main__":
    unittest.main()
