# sekai-client

This crate is licensed under [Apache-2.0](../../LICENSE).

`sekai-client` is the separately versioned Rust facade for the native Sekai
and Chisei core loop. It is intentionally a leaf client crate: the canonical
generated protocol remains in [`sekai-proto`](../sekai-proto), and the control
plane remains authoritative for authentication, authorization, policy, budget,
provider routing, persistence, and receipts.

## Supported surface

The `0.1.x` surface provides:

- HTTPS, loopback HTTP, and Unix-socket tonic transport setup;
- in-memory bearer credentials with redacted `Debug` output;
- principal, namespace, capability, catalog, operation, work-unit, and
  request-correlation metadata;
- bounded per-call deadlines and opt-in retries for safe unary calls;
- typed gRPC status mapping that distinguishes authentication, authorization,
  policy, budget, and transport outcomes;
- cancellable `PlanExecution` and `ExecutePlanStream` calls;
- operation-event reporting and receipt lookup; and
- an explicit native raw tonic escape hatch for unsupported RPCs.

`CoreLoopTransport` is injectable, so deterministic tests and hosts such as
Shikigami do not need a live plane. Stream calls are never retried
automatically. Unary retries require `CallOptions::retryable(true)` and reuse
one request ID across attempts; callers should only enable them for operations
whose server contract is safe to replay.

Receipt reads default to safe unary retries, but
`CallOptions::retryable(false)` remains an explicit opt-out.

`run_core_loop` bounds buffered events by count and encoded bytes (configurable
through `ClientConfig::with_stream_limits`). Hosts that need different
processing semantics can consume the cancellable stream directly.

## Compatibility and migration policy

The crate follows semver within `0.1.x`: additive public API changes are
preferred, and breaking changes require a new minor version before `1.0.0`.
The crate's major protocol dependency is `sekai-proto` `1.x`; generated
bindings are never copied into this package. A consumer should pin compatible
`sekai-client` and `sekai-proto` versions together and migrate from raw tonic
clients by replacing connection, metadata, timeout, error, and stream plumbing
with `CoreLoopClient` calls. Unsupported RPCs can remain on `client.raw()`
until a typed helper is justified.

For registry publication, release a compatible `sekai-proto` version before
`sekai-client`; workspace builds resolve the local path, while registry
consumers resolve the canonical protocol crate independently.

## Offline fixture

The deterministic fixture exercises planning, streamed execution, event
reporting, and receipt correlation without credentials or a live service:

```bash
cargo run -p sekai-client --example core_loop_fixture
```

Live-plane coverage is intentionally optional. The workspace's ordinary
`cargo test` suite remains service-independent; applications may add an
ignored integration test around `CoreLoopClient::connect` when a configured
Sekai Chisei endpoint is available.

## Security boundary

Credentials are accepted only in memory and are never persisted or included in
SDK error text. Reserved authority metadata cannot be supplied through the raw
escape hatch. Every RPC carries the configured authentication metadata so the
server can re-authenticate and re-authorize it against current durable state.
The client does not infer or cache authority from a previous call.
