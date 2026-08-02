# ADR 0013: Govern external evaluator adapters outside the Chisei process

- Status: accepted
- Date: 2026-08-02
- Owners: @Sannrox
- Discussion: none; resolved in [Issue #513](https://github.com/Sannrox/sekai-chisei/issues/513)
- Issue: https://github.com/Sannrox/sekai-chisei/issues/513
- Supersedes: none
- Superseded by: none

## Context

`EvaluatorDefinition` already lets an operator publish namespace-scoped
metadata and bind an exact implementation digest, but the execution registry
previously contained only implementations compiled into the Chisei process.
An integration could publish a plan for a domain evaluator and still receive
`evaluator_unavailable` unless it changed the server binary.

The extension boundary must add domain variability without accepting tenant
code, transferring action authority, or creating a second operation-receipt
authority.

## Decision

Add `external_adapter/v1` as an evaluator execution class. The existing
namespace-authorized `PutEvaluatorDefinition` API may publish an immutable
operator-deployed adapter endpoint alongside the exact implementation digest.
Chisei invokes that endpoint through the bounded
`chisei.external-evaluator-request/v1` JSON contract and validates the normal
closed deterministic result contract before recording the existing step and
operation receipts.

Adapter calls and responses are authenticated with an operator-only
`CHISEI_EVALUATOR_ADAPTER_SHARED_SECRET` HMAC. The response signature binds
the request digest, response digest, and implementation digest. HTTPS is
required for non-loopback endpoints; loopback HTTP is permitted only when
`SEKAI_INSECURE=1` is explicitly set for local development. The adapter
receives no Chisei credentials, ambient capabilities, action authority, or
receipt-writing authority.

`EvaluatorDefinitionRecord` reports executable capability separately from
metadata publication. Missing configuration, unavailable transport, timeout,
invalid output, or exact-digest mismatch fails closed. Existing availability
transitions remain the authority for new plan and manifest resolution, while
historical manifests retain their existing replay semantics.

## Alternatives considered

- **Load executable plugins through the public API.** Rejected because it
  turns the control plane into a native code loader and expands the trust
  boundary to ABI compatibility, sandboxing, restart, supply-chain, and
  process-credential concerns.
- **Keep only compiled registry implementations.** Rejected because domain
  integrations must modify the Chisei binary for every new evaluator.
- **Let namespaces upload or run arbitrary scripts.** Rejected because a
  namespace is a logical authorization boundary, not an operating-system
  sandbox, and scripts would widen the product into a workflow/runtime engine.

## Consequences

The public evaluator definition contract gains an additive adapter endpoint and
capability projection. The existing SQLite/PostgreSQL definition persistence
continues to store the canonical JSON body without a new table or migration.
Operators must deploy and secure the adapter, configure the shared secret, and
monitor its availability. Adapter latency and transport failure become an
explicit `unavailable` path, bounded by the existing evaluator thread and
execution budgets.

The core remains authoritative for namespace authorization, plan resolution,
input/evidence limits, reducer semantics, budgets, audit, lineage, and durable
operation receipts.

## Validation

- Endpoint validation rejects non-TLS remote URLs, userinfo, query strings,
  malformed URIs, and missing external endpoints.
- Registry fixtures prove adapter registrations are namespace scoped.
- The adapter fixture verifies canonical JSON, namespace/digest binding, HMAC
  request and response headers, bounded response parsing, and the closed result
  contract.
- Existing evaluator content digests remain stable when the adapter endpoint is
  empty, preserving replay of definitions published before this ADR.
- Capability records distinguish published metadata from executable runtime
  availability.
