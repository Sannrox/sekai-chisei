# ADR 0066: Evaluate revision-bound ObjectSet descriptors without a query language

- Status: accepted
- Date: 2026-09-13
- Owners: @Sannrox
- Discussion: https://github.com/Sannrox/sekai-chisei/discussions/862
- Issue: https://github.com/Sannrox/sekai-chisei/issues/835 (#835)
- Supersedes: none
- Superseded by: none
- Related: [ADR 0025](0025-storage-enforced-object-security.md)

## Context

`ListObjects` / `ListFilter` already filter, sort, limit, and page one kind.
`Traverse` already walks declared links. Issue #835 needed one evaluateable
descriptor that keeps object-type identity, definition revision,
authorization, and continuation on the same fence. A general query language
was rejected.

## Decision

Accept `sekai.object-set/v1` and `EvaluateObjectSet`. The server evaluates
the descriptor through existing authorized list and one-hop traverse. The
pinned definition digest must match the published revision. Hidden rows and
properties cannot affect members, counts, order, errors, or tokens. The
descriptor, page, and cached set are not authority.

## Alternatives considered

- A general query language or warehouse SQL dialect.
- Treating client-composed `ListObjects` then `Traverse` as a sufficient
  ObjectSet contract.
- Materialized sets or search indexes as a second object authority.

## Consequences

Authenticated clients can compose two property filters, sort, page, and
one declared hop under one revision and one continuation token. Follow-up
subscription work may reuse this descriptor only when that contract
explicitly adopts it.

## Validation

Deterministic Customer → Order fixtures filter two properties, sort, page,
and traverse one declared link without fetching a whole collection.
Wrong types, stale revisions, unsupported operators, and hidden members
fail without disclosure.
