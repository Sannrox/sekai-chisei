# ADR 0016: Publish a dedicated versioned Rust core-loop client

- Status: accepted
- Date: 2026-08-04
- Owners: @Sannrox
- Discussion: [Issue #523](https://github.com/Sannrox/sekai-chisei/issues/523)
- Supersedes: none
- Superseded by: none

## Context

Rust consumers currently assemble tonic connection, authentication metadata,
timeouts, stream handling, and receipt correlation independently. The existing
`sekai-admin-client` is a provider-neutral administration boundary and should
not become an implicit runtime execution API. Issue #523 needs one replaceable
Rust integration boundary for the governed plan/execute core loop without
adding a protocol or gateway surface.

## Decision

Publish a dedicated `sekai-client` leaf workspace crate at version `0.1.0`.
It consumes the canonical generated `sekai-proto` `1.x` crate and provides:

- native tonic setup for HTTPS, loopback HTTP, and Unix sockets;
- in-memory credential attachment and reserved principal, namespace,
  capability, catalog, operation, work-unit, and request metadata;
- bounded deadlines, explicit safe unary retry opt-in, typed status mapping;
- cancellable `PlanExecution` and `ExecutePlanStream` calls;
- operation-event reporting and receipt retrieval; and
- a raw tonic escape hatch whose authority metadata remains SDK-owned.

`CoreLoopTransport` is public and injectable. It is the deterministic test and
host-adapter seam; the SDK does not persist credentials, make policy or
authorization decisions, execute providers, own receipts, or cache authority.
Every call carries the configured authentication context so the server remains
free to re-authenticate and re-authorize against current durable state.

The compatibility policy is additive semver within `0.1.x`, with breaking
changes requiring a new minor version before `1.0.0`. Consumers pin compatible
`sekai-client` and `sekai-proto` versions together. Unsupported RPCs remain
available through the raw escape hatch until a typed helper is justified.
Registry publication releases the compatible `sekai-proto` version before
`sekai-client`; workspace builds use the local path, while external consumers
resolve both packages from their published versions.

## Alternatives considered

- **Extend `sekai-admin-client`:** rejected because administration and governed
  runtime execution have different owners and compatibility expectations.
- **Keep raw tonic clients in consumers:** rejected because it repeats
  security-sensitive metadata, deadline, stream, error, and receipt behavior.
- **Bridge TypeScript or Python from Rust:** rejected because it adds runtime
  packaging dependencies and does not fit native Rust integrations.
- **Add REST or gateway routes:** rejected because gRPC remains the native
  system-of-record protocol and the gateway is a compatibility translator.

## Consequences

Rust consumers gain one explicit migration target and deterministic fixture
support, while the workspace gains a separately versioned package and a small
protocol compatibility obligation. Stream retries remain prohibited because a
provider execution may already have effects; unary retries require explicit
caller opt-in and reuse one request ID. Live endpoint checks remain optional
and are not required by the ordinary offline test suite. Registry publication
has an explicit protocol-before-facade order.

Shikigami can adopt the crate in its follow-up without reimplementing the
transport, metadata, timeout, error, or stream plumbing. Domain-specific
helpers and authority stay outside this crate.

## Validation

The crate's deterministic unit tests cover metadata binding, reserved metadata
rejection, namespace isolation, deadlines, typed authorization/policy errors,
retry boundaries, ordered streaming, cancellation, and receipt correlation.
`examples/core_loop_fixture.rs` exercises plan, execute, stream, event, and
receipt calls without credentials or a live plane. Normal workspace tests stay
service-independent; a consumer may add an ignored live-plane integration test
when an endpoint is available.
