# ADR 0058: Certify model-platform adapters against evaluation evidence

- Status: accepted
- Date: 2026-08-31
- Owners: @Sannrox
- Discussion: https://github.com/Sannrox/sekai-chisei/discussions/752
- Issue: https://github.com/Sannrox/sekai-chisei/issues/713 (#713)
- Supersedes: none
- Superseded by: none
- Related: [ADR 0055](0055-connector-certification.md),
  [ADR 0013](0013-governed-external-evaluator-adapters.md)

## Context

Provider profiles already describe capability matrices and the Responses
harness. They do not yet issue a digest-bound certification after a
model-platform adapter passes capability, streaming, usage, fallback,
and receipt protocol fixtures. Without that record, a passing suite can
be mistaken for a live grant, and evaluation-evidence identity from
Discussion 752 stays unused.

## Decision

Accept `sekai.model-platform-certification/v1` as a certification
envelope that pins `sekai.evaluation-evidence/v1`. Identity is
`(namespace, certification_id)`. Two domain-neutral adapters
(`adapter.model.responses`, `adapter.model.messages`) certify against
deterministic protocol fixtures. Unsupported capability and ambiguous
usage fail closed. Exact digest replay is idempotent. Revocation is
terminal and bound into the evidence digest. Certification is not a
runtime grant.

SQLite is the reference store. PostgreSQL stays unavailable.

## Alternatives considered

Treating a passing provider suite as authorization was rejected because
live grants must be rechecked. Calling live model endpoints from CI was
rejected because conformance must be deterministic. Reusing connector
Ed25519 signatures was rejected because Discussion 752 pins evaluation
evidence, not a signer.

## Consequences

Operators certify, retrieve, verify, and revoke through
`sekaictl admin providers`. Existing provider routing and receipts
remain the runtime path.

## Validation

Two adapter fixtures cover capability, streaming, usage, fallback, and
receipt protocol conformance.
