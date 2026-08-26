# ADR 0029: Share namespaces through grant-scoped signed snapshots

- Status: accepted
- Date: 2026-08-26
- Owners: @Sannrox
- Discussion: none; decided in the implementation pull request for #697
- Issue: https://github.com/Sannrox/sekai-chisei/issues/697
- Supersedes: none
- Superseded by: none

## Context

The federation profile (`sekai.federation-profile/v1`) already pins peer
verifying keys, joins planes, and denies remote promote, kill, and budget
control. Peer compliance import proves identity and integrity of audit
bundles. It does not yet share namespace facts. Without a separate grant and
replica boundary, a valid peer signature could be mistaken for local write
authority, overwrite local objects, or disclose hidden markings.

## Decision

`sekai.namespace-snapshot/v1` exports and imports a bounded, content-addressed,
site-signed bundle of **visible typed objects** for one namespace.

1. A peer signature proves which site produced the bundle. An explicit local
   **peer grant** (peer, namespace, optional kinds, optional classification
   ceiling, validity window) is required before import. Signature, join, or
   health is never a grant.
2. Export includes only objects the exporting actor is authorized to see.
   Hidden or marking-denied objects are omitted. The bundle may record
   `hidden_omitted=true` but never a hidden count or hidden identifiers.
3. Import fails closed before local use on untrusted signers, exporter
   identity that does not match the trusted signer, missing grants, stale
   validity or same-or-older sequences with a different digest, tampered
   digests, revoked grants, residency conflicts, policy-pin mismatch, or
   facts outside the grant. Export sequences are reserved atomically.
4. Accepted facts are stored as replicas with `write_authority=false` and
   `permit_authority=false`. They never authorize local permits, policy,
   budgets, leases, or writes. A colliding local object is recorded as a
   conflict and is not overwritten.
5. Re-import of the same `(namespace, snapshot_digest, peer)` tuple is
   idempotent. SQLite is the reference store. PostgreSQL fails closed as
   unavailable until federation persistence parity exists.

## Alternatives considered

Live remote graph access was rejected because it would share write authority
and fail when a peer is down. Merging imported objects into `sekai_objects`
was rejected because replicas would become local write targets. Treating a
trust-root pin as a namespace grant was rejected because identity is not
authorization.

## Consequences

Operators can move a signed, inspectable namespace snapshot between two local
planes without creating a shared transaction or remote control channel.
Follow-up work may add PostgreSQL parity, gRPC transport, and the later
conflict, provenance, and revocation Issues that depend on this contract.

## Validation

Deterministic fixtures cover authorized round-trip, hidden omission, policy
pins, ungranted peers, stale windows, tamper, wrong signer, revocation,
residency conflict, and local-write conflicts. Community PostgreSQL remains
an explicit unavailable surface.
