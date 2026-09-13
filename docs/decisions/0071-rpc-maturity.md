# ADR 0071: Classify public RPCs by backend and consumer evidence

- Status: accepted
- Date: 2026-09-13
- Owners: @Sannrox
- Discussion: source Issue [#871](https://github.com/Sannrox/sekai-chisei/issues/871)
- Issue: https://github.com/Sannrox/sekai-chisei/issues/871 (#871)
- Supersedes: none
- Superseded by: none
- Related: [ADR 0019](0019-dual-capability-catalogs.md), [ADR 0058](0058-model-platform-certification.md), [ADR 0059](0059-autonomous-envelopes.md)

## Context

The public surface is 129 Sekai and 32 Chisei RPCs. Operators cannot tell which
RPCs are runnable against real backends. Capability `product_tier` describes
catalog packs; it does not mark wire maturity or gate invocation.

## Decision

Every public RPC is classified `stable`, `experimental`, or `remove` from
backend and consumer evidence. The table in [rpc-maturity.md](../rpc-maturity.md)
is a projection, not a second authority.

- `stable` requires a real (non-fixture) backend. The default public loop and
  its required siblings stay at most 60 RPCs.
- `experimental` RPCs keep their wire contract, authorization, and receipts.
  Invocation requires `SEKAI_EXPERIMENTAL_RPCS=1` or the `experimental-rpcs`
  Cargo feature. Both are off by default.
- `remove` is a deprecation classification only. Deletion is a later
  major-version change set. Removal of an RPC that later has an external
  consumer needs a Design Discussion first.
- `DiscoverCapabilities` reports `sekai.rpc.experimental` on the core pack.
  Visibility is not a grant.
- Stable SDK generation omits experimental and remove backing RPCs without a
  denylist.

Fixture-only paths are not reachable in the default build.

## Alternatives considered

- Use `product_tier` as maturity. Rejected: that redefines dual-backend and
  catalog-pack claims.
- Delete experimental RPCs in this change set. Rejected: the Issue keeps
  removal for a later major version and preserves wire contracts that still
  have real backends.

## Consequences

Default servers reject experimental and remove RPCs with
`FAILED_PRECONDITION`. Operators who need those paths enable the flag.
Security review and SDK generation shrink to the stable set.

## Validation

A deterministic test compares the checked-in table and `docs/rpc-maturity.md`
with both proto services, asserts at most 60 stable RPCs, and proves the
default gate cannot reach an experimental RPC.
