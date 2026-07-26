# Capability projection SDKs

The Rust projection in `src/capability_projection.rs` is the reference adapter.
The TypeScript and Python modules here are deliberately thin bindings over its
serialized `ProjectedCapability` contract. They do not discover extra tools,
make policy decisions, or hold credentials.

For **namespace-scoped typed codegen** from a selected capability subset (issue
#299), see `docs/capability-codegen.md` and
`src/capability_codegen.rs`.

All clients require the caller to supply an operation ID and bind the exact
principal, namespace, capability name, and operation ID to the native gRPC
metadata contract. The shared fixture under
`tests/fixtures/capability_projection/` detects version, identity, error, and
correlation drift.

Run the standalone conformance checks with:

```bash
node --experimental-strip-types --test sdk/typescript/capability.test.ts
python3 -m unittest discover -s sdk/python -p 'test_*.py'
```
