# ADR 0053: Exchange federation traffic through bilateral network contracts

- Status: accepted
- Date: 2026-08-31
- Owners: @Sannrox
- Discussion: none; decided in Issue #708 and this pull request
- Issue: https://github.com/Sannrox/sekai-chisei/issues/708 (#708)
- Supersedes: none
- Superseded by: none
- Related: [ADR 0041](0041-governed-federation-conflicts.md),
  [ADR 0042](0042-governed-federation-revocation.md)

## Context

Federation already pins peers, imports signed snapshots, records conflicts,
and revokes shared authority. Those primitives do not yet make a bilateral
contract the unit of exchange for governed requests, evidence, and outcomes.
Without that contract, peer health or signatures can be mistaken for local
write authority.

## Decision

A `sekai.federation-network-contract/v1` object is identified by
`(namespace, contract_id)`. It pins local and peer site identities, a closed
set of exchange kinds (`request`, `evidence`, `outcome`), and a residency
class. Accepted contracts admit digest-bound exchanges. Peer loss disconnects
the contract without deleting history. Reconnect restores accepted status.
Revocation is terminal for that contract identity.

An exchange is observational. It never grants local permits, policy, budgets,
leases, or writes. The admitting owner attests origin and payload digest.
Cryptographic peer verification remains the signed snapshot-import path.
Untrusted origin, mismatched residency, unknown kinds, disconnected peers,
and revoked contracts fail closed. Exact replay of an exchange is idempotent.

SQLite is the reference store. PostgreSQL stays unavailable.

## Alternatives considered

Treating peer health or signatures as local authorization was rejected because
each plane must retain write authority. Cross-plane transactions were rejected
because they would share writes. A marketplace of network memberships was
rejected because it would expand product surface beyond bilateral contracts.

## Consequences

Operators accept contracts, exchange envelopes, mark peer loss, reconnect, and
revoke through `sekaictl admin network`. Existing peer join, snapshot import,
conflict, and revocation surfaces remain.

## Validation

Deterministic fixtures cover authorized request/evidence/outcome exchange,
idempotent replay, peer loss, reconnect, residency conflict, tamper, foreign
origin, revocation, and foreign owners.
