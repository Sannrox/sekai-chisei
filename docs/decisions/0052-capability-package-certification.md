# ADR 0052: Certify capability packages against an immutable digest

- Status: accepted
- Date: 2026-08-31
- Owners: @Sannrox
- Discussion: none; decided in Issue #707 and this pull request
- Issue: https://github.com/Sannrox/sekai-chisei/issues/707 (#707)
- Supersedes: none
- Superseded by: none
- Related: [ADR 0051](0051-versioned-client-packages.md)

## Context

#690 asked for a portable capability-package contract. The earlier package
install/trust vertical was removed because it had no runtime consumer and
could be mistaken for a grant. Reviewers still need to bind signer, manifest,
compatibility, tests, and revocation to one independently verifiable digest.

## Decision

A `sekai.capability-package-certification/v1` object is identified by
`(namespace, certification_id)`. It pins a logical `package_id`, a canonical
package digest over members and compatibility, signer identity, test-suite and
test-result digests, and a certification digest over those pins plus
namespace, certification identity, owner, and predecessor. Revocation is a
lifecycle overlay and does not rewrite the certification digest.

Closed member kinds are `change_set`, `action_type`, `ontology`, and
`evaluation`. Certification is not a runtime grant. Live grants are rechecked
elsewhere. Exact replay of a live certification is idempotent. Content or
dependency change yields a different digest and fails verification of the
prior record. Recertification supersedes the previous live certification and
preserves it. Revocation is terminal for that certification identity and
remains inspectable.

SQLite is the reference store. PostgreSQL stays unavailable.

## Alternatives considered

Restoring the removed install/trust vertical was rejected because
certification would become authority. Treating signatures or discovery as
grants was rejected because invocation still requires live authorization.
Silently rewriting a certification in place was rejected because history and
independent verification would be lost.

## Consequences

Operators certify, retrieve, independently verify, and revoke packages through
`sekaictl admin packages`. Client SDK publications remain ADR 0051.

## Validation

Deterministic fixtures cover authorized certification, independent
verification, content and dependency invalidation, replay, recertification
history, revocation, hidden fields, unknown member kinds, and foreign owners.
