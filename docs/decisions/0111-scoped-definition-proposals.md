# ADR 0111: Scoped contexts publish definition drafts through proposals

- Status: accepted
- Date: 2026-10-16
- Owners: @Sannrox
- Discussion: none — resolved in Issue #1542
- Issue: #1542
- Supersedes: none
- Superseded by: none
- Related: [ADR 0079](0079-evaluation-promotion-gate.md),
  [ADR 0093](0093-agent-drafts-use-definition-members.md),
  [ADR 0094](0094-scoped-definition-draft-authoring.md)

## Context

[ADR 0094](0094-scoped-definition-draft-authoring.md) admitted scoped
authenticated contexts for definition draft authoring and left proposal
approval, merge, and publication admission unchanged until Agent promotion
had the [ADR 0079](0079-evaluation-promotion-gate.md) certification
integration. That integration now refuses an Agent merge without current,
non-revoked, baseline-passing certification, and the certification gate and
published revision history are already scoped-admitted reads. A scoped
builder can draft and inspect every gate but cannot publish.

## Decision

1. Admit scoped contexts for qualified `sekai.SekaiService`
   `GetDefinitionProposal`, `CreateDefinitionProposal`,
   `ApproveDefinitionProposal`, and `MergeDefinitionProposal`, through the
   server-established RPC identity. They stay experimental.
2. Every existing check applies unchanged: namespace write scope and tenant
   context, revision read grants on base and candidate, administration of
   every changed member, a recorded approval before merge, the exact expected
   published digest, the ADR 0079 certification gate including
   self-certification refusal, request-bound idempotency, and actor
   attribution to the authenticated subject.
3. Approve, merge, and close now also authorize reads of both the base and
   candidate revisions, as create and get already did. Approval or merge
   discloses both revisions, so administering the changed members alone is
   not enough.
4. `CloseDefinitionProposal` stays unadmitted; no scoped consumer needs it.

## Alternatives considered

- Keep publication operator-only. Rejected because a scoped builder tool
  could then never publish what it drafts, and the certification gate already
  guards promotion independently of the caller's credential kind.
- Add a scoped two-person rule. Rejected because separation is already
  enforced where it matters: an author cannot bind the certification that
  admits their own Agent change.

## Consequences

- Scoped builder tools can publish definition drafts, bounded by grants and
  certification. No schema, store, or RPC shape changes.

## Validation

- Real TCP scoped test: create, get, approve, and merge publish a certified
  Agent revision with a receipt; merge without certification returns
  `agent_promotion_requires_certification`; read-only scope, a foreign
  namespace, and a subject without member administration are refused; a
  replayed merge returns the same receipt; a caller who administers the
  changed member but cannot read an unchanged one cannot approve or merge;
  `CloseDefinitionProposal` stays
  refused behind a spoofed method header.
- Routing test: the four methods are admitted only on `sekai.SekaiService`.
