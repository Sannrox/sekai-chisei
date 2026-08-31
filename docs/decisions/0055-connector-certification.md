# ADR 0055: Certify connectors against an immutable digest

- Status: accepted
- Date: 2026-08-31
- Owners: @Sannrox
- Discussion: none; decided in Issue #710 and this pull request
- Issue: https://github.com/Sannrox/sekai-chisei/issues/710 (#710)
- Supersedes: none
- Superseded by: none
- Related: [ADR 0052](0052-capability-package-certification.md),
  [ADR 0020](0020-shared-type-revisions-and-object-sync.md)

## Context

Object sync already ships one bounded GitHub Issue/PullRequest connector
and a conformance SDK. Those primitives do not yet issue a signed,
revocable verification record after the connector passes authority and
failure conformance. Without that record, a passing suite can be
mistaken for a live grant.

## Decision

Accept `sekai.connector-certification/v1`. Identity is
`(namespace, certification_id)` over the catalogued GitHub object-sync
connector, its type digest, producer identity, Ed25519 public key, and
test digests. The signer digest is the SHA-256 of the public key.
Certification is an Ed25519 signature over the certification digest,
not a runtime grant. Exact replay is
idempotent. Recertification uses a predecessor. Revocation is terminal
for that certification identity. Hidden secret fields, unknown
connectors, package/type-digest change, and foreign owners fail closed.

SQLite is the reference store. PostgreSQL stays unavailable.

## Alternatives considered

Treating a passing adapter suite as authorization was rejected because
live grants must be rechecked. A connector marketplace was rejected by
ADR 0020. Embedding credentials in the verification record was rejected
because receipts and diagnostics stay value-free.

## Consequences

Operators certify, retrieve, verify, and revoke through
`sekaictl admin connectors`. Existing source-batch admission remains
the write path.

## Validation

Deterministic fixtures cover read, mutate/recertify, retry, deny,
replay, secret, package change, and revocation.
