# ADR 0089: Park approval-gated Action instances and decide them explicitly

- Status: accepted
- Date: 2026-09-23
- Owners: @Sannrox
- Discussion: https://github.com/Sannrox/sekai-chisei/discussions/1096
- Issue: https://github.com/Sannrox/sekai-chisei/issues/1084 (#1084)
- Supersedes: none
- Superseded by: none
- Related: [ADR 0063](0063-object-action-describe-preview.md),
  [ADR 0081](0081-evaluate-reads-mikura-library.md)

## Context

An Action policy may decide `require_approval`. Admission persisted such an
instance as `denied` with reason "requires approval (not yet supported)".
Callers could not close the loop: no RPC granted or denied the instance, and
resubmitting after an out-of-band yes minted a second instance, so
idempotency and receipts diverged. `PreviewObjectAction` reports
`require_approval` and must stay observational (ADR 0063).

In mature governed-action systems, an approval-gated submission becomes a
pending request that named approvers accept or reject. Acceptance validates
the action again against current data when it applies. Rejection is
terminal. The requester is never their own approver.

## Decision

- **Parked, not denied.** A `require_approval` admission persists the
  instance as `parked`: no object write, no effects, an open receipt, and a
  digest of the target object. `denied` keeps meaning a policy, budget,
  criterion, or reviewer refusal.
- **Who decides.** `GovernedActionType.approvers` names the principals who
  may decide, versioned with the type. With no declaration, only namespace
  administrators decide. The submitter never decides their own instance.
  Every refusal, including an unknown instance, answers the same bounded
  `access denied`.
- **Grant resumes the same instance** against current state. The type must
  still be enabled, the parameters must still validate, the submission
  criteria and policy are evaluated again (the approval satisfies only
  `require_approval`), and the target object must be unchanged. Any
  difference ends the instance `denied` with a bounded reason such as
  `stale_on_resume`, with no partial write. A passing grant writes the
  object, effects, and receipt exactly as a direct admit does.
- **Deny** is terminal (`denied_by_approver`).
- **Idempotency.** A replayed submit returns the parked instance and never
  mints a second. The first decision wins. Repeating it replays the recorded
  outcome, and a conflicting later decision fails `FAILED_PRECONDITION`.
- **Receipt and audit.** The decision completes the instance's own receipt
  with an `approval_decided` event naming the approver, so
  `GetOperationReceipt` closes the loop. Audit records
  `decide_action_instance`.
- **Wire.** `DecideActionInstance { instance_id, decision, reason }` sits
  beside `SubmitActionInstance` on `SekaiService`, where admission is served.
  It is `experimental` until a sekaictl or SDK consumer ships.
- **Backends.** SQLite ships first. Community PostgreSQL parks instances but
  answers `UNAVAILABLE` for decisions and is not advertised for them.
- **No implicit expiry.** A parked instance waits for an explicit decision.

## Alternatives considered

- Keep persisting `denied` and resubmit after an out-of-band yes: rejected,
  because the instance is a dead row and idempotency and receipts diverge.
- Reuse `ApproveDefinitionProposal`: rejected, because that governs
  definition authorship, not Action admission.
- External-action permit redeem: rejected, because it is a different
  lifecycle.

## Consequences

`require_approval` types no longer end denied at submit. Clients see
`parked` until a decision. Approvers must be declared on the type, or
namespace administrators decide. Combined Split reserves one budget unit
at submit. A grant does not charge again, and a denied approval keeps that
unit, as submit-time denials in Split already do. A grant whose receipt
cannot be recorded undoes its object write and returns the instance to
`parked`, so the decision can be retried.

## Validation

- Admission unit tests cover park, grant, deny, replay, conflicting
  decisions, submitter and foreign-principal refusal, the namespace-admin
  fallback, and the stale-object fence.
- `tests/native_server_smoke.rs::spawned_binary_parks_an_action_until_a_named_approver_grants_it`
  proves the path through the shipped server with three authenticated
  principals.
