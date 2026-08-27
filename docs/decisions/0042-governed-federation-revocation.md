# ADR 0042: Revoke shared federation authority as governed objects

- Status: accepted
- Date: 2026-08-27
- Owners: @Sannrox
- Discussion: https://github.com/Sannrox/sekai-chisei/discussions/780
- Issue: https://github.com/Sannrox/sekai-chisei/issues/703
- Supersedes: none
- Superseded by: none
- Related: [ADR 0029](0029-signed-namespace-snapshots.md),
  [ADR 0034](0034-cross-site-import-provenance.md),
  [ADR 0041](0041-governed-federation-conflicts.md)

## Context

Signed snapshots, provenance hops, and conflict records admit peer facts as
non-authoritative replicas. Grant flags and membership leave can withdraw some
access, but they do not store peer, signer, grant, and snapshot-revision
withdrawals as inspectable objects with bounded propagation evidence. Without
that record, a reconnect or a later snapshot can look like restored authority,
and a disconnected plane can overstate that the peer received the withdrawal.

## Decision

An operator withdrawal of peer, signer, grant, or snapshot-revision authority
admits a `sekai.federation-revocation/v1` record identified by
`(subject_kind, subject_id)`.

The record is local write-plane authority only. It never grants write or permit
rights and never deletes snapshots, conflicts, provenance hops, or prior
grants. Verify and import that depend on an active subject fail closed before
replica use. Unknown and revoked identities return the same unavailable
result.

Propagation is plane-local. On admit, acknowledgement is `unknown`. A later
import that still presents the revoked subject records `denied`. A later
accepted import that no longer presents a revoked snapshot revision records
`reconciled`. Reconnect cannot resurrect revoked authority.

Re-admit of the same subject is idempotent. SQLite is the reference store.
PostgreSQL stays unavailable.

## Alternatives considered

Flipping only an enabled bit or membership flag would let reconnect look like
an implicit restore. Broadcasting revocation as a remote control verb would
make a peer signature into the other plane's authority. Deleting snapshots or
provenance on revoke would leave reconnect and later review without evidence.

## Consequences

Operators can withdraw shared authority immediately on this plane, inspect
whether a reconnect still asserted the withdrawn subject, and keep source
history. Follow-up work may add PostgreSQL parity and gRPC transport.

## Validation

Pure tests cover immediate local denial for peer, signer, grant, and snapshot
revision subjects, idempotent re-admit, retained replicas, unknown-identity
non-disclosure, denied reconnect observation, and revision reconcile when a
later distinct digest is accepted.
