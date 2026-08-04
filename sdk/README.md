# Sekai/Chisei SDKs

The SDKs are thin, server-side facades over the existing native gRPC contracts.
They do not add a REST route, replace gRPC, discover authority, make policy
decisions, or hold credentials beyond the in-memory bearer token needed to
attach request metadata. Every call is still authorized by the control plane.

The supported core-loop helpers are:

```text
define ontology → seed facts → plan/execute → inspect receipt
```

The transport-neutral clients accept an injected transport for deterministic
tests and adapters. Optional native gRPC transports are provided for Node.js
and Python applications.

For **namespace-scoped typed codegen** from a selected capability subset (issue
#299), see `docs/capability-codegen.md` and
`src/capability_codegen.rs`.

Callers may supply an operation ID (the core-loop helper generates one when it
is omitted); every call binds the exact principal, namespace, capability name,
and operation ID to the native gRPC metadata contract. The shared fixture under
`tests/fixtures/capability_projection/` detects version, identity, error, and
correlation drift.

## TypeScript

The TypeScript package is intended for Node.js server or desktop-host code.
Install the local package with the native transport dependencies:

```bash
npm install ./sdk/typescript @grpc/grpc-js @grpc/proto-loader
```

Use HTTPS for remote targets. Plain HTTP is accepted only for loopback targets
unless `allowInsecureRemote` is explicitly enabled by the host application.
When the package is installed outside this repository, pass `protoRoot` to the
canonical checkout's `proto/` directory; the SDK intentionally does not bundle
a second protocol snapshot.

```ts
import { SekaiChiseiClient } from "@sannrox/sekai-chisei-sdk";

const client = await SekaiChiseiClient.connect({
  target: process.env.SEKAI_CHISEI_TARGET ?? "http://127.0.0.1:50051",
  token: process.env.SEKAI_AUTH_TOKEN,
  principal: "aldunis-code",
  namespace: "demo",
  catalogVersion: "catalog-v1",
});

try {
  const result = await client.runCoreLoop({
    namespace: "demo",
    schema: { kind: "service", description: "A deployable service" },
    objects: [{ id: "service-1", kind: "service", name: "billing-api" }],
    execution: {
      namespace: "demo",
      spec: "summarize the service health",
      task_type: "diagnostic",
      max_tokens: 256,
    },
    operationId: "operation-1",
  });
  console.log(result.receipt.complete, result.plan.plan_id);
} finally {
  client.close();
}
```

`executePlanStream` returns an async iterable and accepts an `AbortSignal`.
Streams are not transparently retried because replaying a provider execution is
not generally safe. Unary retries are opt-in with `retryable: true` and should
only be used for idempotent or read operations.

Advanced callers can use `client.raw.unary(...)` and `client.raw.stream(...)`.
Reserved authority metadata cannot be overridden through that escape hatch.

## Python

The Python facade has no mandatory runtime dependency. Install the optional
native transport support with:

```bash
python3 -m pip install './sdk/python[grpc]'
```

The consuming application generates Python bindings from the repository's
canonical protocol files and passes them to `GrpcBindings`; the SDK does not
vendor a second protobuf snapshot:

```bash
python3 -m grpc_tools.protoc \
  -I proto \
  --python_out=. \
  --grpc_python_out=. \
  proto/sekai.proto proto/chisei.proto
```

```python
import os

from sekai_client import ClientConfig, SekaiChiseiClient
from sekai_grpc import GrpcBindings
import chisei_pb2, chisei_pb2_grpc, sekai_pb2, sekai_pb2_grpc

client = SekaiChiseiClient.connect(
    ClientConfig(
        target="http://127.0.0.1:50051",
        token=os.environ.get("SEKAI_AUTH_TOKEN"),
        principal="aldunis-code",
        namespace="demo",
    ),
    GrpcBindings(
        sekai_stub=sekai_pb2_grpc.SekaiServiceStub,
        chisei_stub=chisei_pb2_grpc.ChiseiServiceStub,
        sekai_messages=sekai_pb2,
        chisei_messages=chisei_pb2,
    ),
)
result = client.run_core_loop(
    "demo",
    [{"id": "service-1", "kind": "service", "name": "billing-api"}],
    {"namespace": "demo", "spec": "summarize the service health"},
)
print(result["receipt"]["complete"])
client.close()
```

`execute_plan_stream` returns a cancellable iterator. Call `cancel()` when the
host stops consuming the stream. Unary retries are explicit and stream retries
are never automatic.

## Conformance and local checks

Run the standalone conformance checks with:

```bash
node --experimental-strip-types --test sdk/typescript/capability.test.ts
node --experimental-strip-types --test sdk/typescript/client.test.ts
node --experimental-strip-types --test sdk/typescript/grpc.test.ts
python3 -m unittest discover -s sdk/python -p 'test_*.py'
npm --prefix sdk/typescript run build
```

The shared core-loop fixture is
`tests/fixtures/sdk_core_loop/v1.json`. It checks metadata, capability scope,
operation correlation, call ordering, streaming, receipt lookup, retries, and
stable error mapping without requiring a live service or credentials.

## Rust

The native Rust facade is published as the separately versioned workspace crate
[`sekai-client`](../crates/sekai-client/). It consumes the generated
[`sekai-proto`](../crates/sekai-proto/) package, supports injected transports
for offline hosts and tests, and provides tonic setup for HTTPS, loopback HTTP,
and Unix sockets. See the crate README and
[ADR 0016](../docs/decisions/0016-versioned-rust-core-loop-client.md) for the
compatibility and migration policy.

Run its credential-free core-loop fixture with:

```bash
cargo run -p sekai-client --example core_loop_fixture
```
