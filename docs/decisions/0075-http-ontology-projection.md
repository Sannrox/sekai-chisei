# ADR 0075: HTTP/JSON ontology is a projection of stable gRPC

- Status: accepted
- Date: 2026-09-14
- Owners: @Sannrox
- Discussion: https://github.com/Sannrox/sekai-chisei/discussions/902
- Issue: https://github.com/Sannrox/sekai-chisei/issues/874 (#874)
- Supersedes: none
- Superseded by: none
- Related: [ADR 0071](0071-rpc-maturity.md),
  [ADR 0066](0066-object-set-evaluate.md)

## Context

The native ontology and Action contract is gRPC. Browser and SDK hosts
re-implement pagination, errors, and auth. The compatible HTTP gateway is a
Chisei *entry path*, not an object resource model. Issue #874 asked whether
to publish one versioned HTTP/JSON contract.

## Decision

1. The proto and the ADR 0071 table remain the contract system of record.
   HTTP/JSON is a generated projection of `stable` RPCs. It is not a
   hand-authored second resource model.
2. Authorization, revision binding, cursors, and hidden-row rules are the
   same on every transport. A hidden object stays one unavailable shape.
3. Streaming and subscription RPCs stay on gRPC. This ADR does not invent
   HTTP long-poll substitutes.
4. Generated clients are reproducible in CI. Experimental RPCs stay behind
   the existing invocation gate.
5. An HTTP MCP endpoint, if added, reuses this projection and bearer
   principal. It is not a second policy path.

## Alternatives considered

- OpenAPI-first as a new resource graph. Rejected: two sources of truth.
- gRPC-only, including for browsers. Rejected: hosts already fork HTTP
  layers; a projection is cheaper than requiring gRPC everywhere.

## Consequences

#875 implements the projection. Latency versus gRPC is an #875 measurement,
not a reason to invent a second model.

## Validation

A stable RPC has the same authorization outcome on gRPC and HTTP. An
experimental RPC is refused on HTTP in the default build. Cursor tokens are
not object authority.
