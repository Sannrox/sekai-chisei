# ADR 0034: Preserve an immutable provenance chain on imported assertions

- Status: accepted
- Date: 2026-08-26
- Owners: @Sannrox
- Discussion: https://github.com/Sannrox/sekai-chisei/discussions/761
- Issue: https://github.com/Sannrox/sekai-chisei/issues/700
- Supersedes: none
- Superseded by: none
- Related: [ADR 0029](0029-signed-namespace-snapshots.md),
  [ADR 0041](0041-governed-federation-conflicts.md)

## Context

ADR 0029 admits grant-scoped signed namespace snapshots as non-authoritative
replicas. After import, an operator still cannot walk an imported assertion
back to the signed source evidence through later relays. Without that chain,
peer signatures or availability can be mistaken for local authority, and
hidden evidence can leak through denial differences.

## Decision

Every accepted imported fact stores an immutable
`sekai.federation-provenance/v1` chain. The exporter signs each hop. The first
hop is the original source snapshot. Later hops record the admitting signer,
the replica transform, and the grant-and-digest verification. Re-export copies
the stored chain, appends newly signed hops, and never rewrites earlier ones.

A downstream importer verifies every hop signature against an enabled trust
root for that hop's site. Each hop binds the digest of the previous hop, so a
relay cannot delete or reorder history. Missing origin pins fail closed.
Legacy bundles without hops stay inspectably empty until the origin re-exports.
Re-export also applies the exporting actor's marking visibility, reserves
hidden local object ids, and prefers the newest live imported assertion when
object ids collide.

The chain is inspectable only when the caller can already read the imported
fact under a live grant. Hidden, unknown, revoked, or ungranted assertions
return the same unavailable result. Import remains a non-authoritative
replica: signatures prove identity only.

SQLite is the reference store. PostgreSQL remains explicitly unavailable.

## Alternatives considered

Treating a valid peer signature as local write authority was rejected because
it would collapse two write planes. Dropping source evidence after import
would make later revocation and hidden-evidence review unverifiable.
Rewriting an admitted chain on reconnect would manufacture a new history.
Accepting relay-supplied hops without signatures would let a trusted relay
forge origin history.

## Consequences

Operators can inspect multi-hop source, signer, transform, and verification
evidence for an imported assertion. Conflicted local objects still are not
overwritten. Follow-up work may add PostgreSQL parity and gRPC transport.

## Validation

Deterministic fixtures cover authorized first-hop chains, multi-hop re-export,
identical unavailable errors for hidden and missing identities, and revoked
grant reads.
