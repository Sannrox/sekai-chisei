# ADR 0041: Preserve concurrent federation assertions as governed conflicts

- Status: accepted
- Date: 2026-08-27
- Owners: @Sannrox
- Discussion: https://github.com/Sannrox/sekai-chisei/discussions/778
- Issue: https://github.com/Sannrox/sekai-chisei/issues/699
- Supersedes: none
- Superseded by: none
- Related: [ADR 0029](0029-signed-namespace-snapshots.md),
  [ADR 0034](0034-cross-site-import-provenance.md),
  [ADR 0042](0042-governed-federation-revocation.md)

## Context

ADR 0029 admits grant-scoped signed snapshots as non-authoritative replicas and
records colliding local object ids. ADR 0034 preserves provenance hops. Neither
stores both claims as an inspectable, resolvable record. Without that record,
peer signatures or sequence order can be mistaken for local authority, and
reconnect can manufacture a winner.

## Decision

A local object that collides with a verified peer snapshot fact becomes a
`sekai.federation-conflict/v1` record identified by `(namespace, object_id)`.

The record stores both claims as source identities plus content digests. Bodies
remain in the local object store and the peer snapshot. The conflict never
grants write or permit authority. Resolution is an explicit audited choice of
one stored claim and does not rewrite source objects, replicas, or provenance
hops. Reopen reverses the current resolution and keeps the prior choice in
history. Re-import of the same peer digest is idempotent. A new distinct peer
claim reopens the conflict without deleting earlier claims.

Untrusted, ungranted, stale, tampered, revoked, hidden, or residency-conflicting
peer data still fails closed before a conflict is admitted.

SQLite is the reference store. PostgreSQL stays unavailable.

## Alternatives considered

Last-write or sequence-order wins would let a peer signature become local
authority. Merging the peer body into `sekai_objects` would turn replicas into
write targets. Recording only object ids would leave both claims and reversible
resolution uninspectable.

## Consequences

Operators can inspect concurrent assertions, choose a claim, and reopen that
choice without rewriting source history. Follow-up work may add PostgreSQL
parity and gRPC transport.

## Validation

Pure tests cover admission of both claims, idempotent replay, unknown-claim
denial without catalog disclosure, reversible resolution that leaves the local
object unchanged, and snapshot-import admission of a governed conflict.
