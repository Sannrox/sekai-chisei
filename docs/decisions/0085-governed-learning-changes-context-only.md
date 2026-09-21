# ADR 0085: A pinned governed learning changes context only

- Status: accepted
- Date: 2026-09-21
- Owners: @Sannrox
- Discussion: https://github.com/Sannrox/sekai-chisei/discussions/1099
- Issue: https://github.com/Sannrox/sekai-chisei/issues/1091 (#1091)
- Supersedes: none
- Superseded by: none
- Related: [ADR 0043](0043-reversible-learning-changes.md),
  [ADR 0071](0071-rpc-maturity.md)

## Context

The verification loop records a learning and, since #714, lets an operator
inspect, approve, activate, and roll it back. The next `PlanExecution` still
did not consume an activated learning as governed data; the only alternatives
were pasting text or letting the planner retrieve memory without an explicit
binding. Discussion #1099 asked what a pinned learning may change: context
only, context plus a route suggestion, or context plus route plus tool
allowlist.

## Decision

A caller may pin one learning on one plan with
`ExecutionInput.learning_pin` (`learning_id` and `candidate_digest`). A pinned
learning changes **context only**.

- Learned data informs a plan and never authorizes one. Routes, tools, policy,
  and budget are granted by operator-owned configuration and are unchanged by a
  pin. Only the learning's bounded `title` and `prevention` become context,
  rendered as untrusted data on a single line. Its reasoning and target
  identity are not disclosed. The text is added after every routing and
  review-policy step, so none of them can read it.
- The ordinary disclosure rules apply unchanged. The caller must be able to
  read the learning object exactly as with ordinary learning retrieval, since
  activation grants no object access. The property-level egress filter applies
  to `title` and `prevention`: on a route that may not receive them (an
  external provider without the operator's external-property allowlist, which
  is part of the approved digest) the pin is refused rather than dropped.
- A pin is usable only when the learning has an active
  `chisei.learning-change/v1` record in the request's namespace, the pinned
  digest equals the digest that was approved and activated, the learning object
  still matches that digest, and the record is not under reconciliation.
  Proposed, approved, rolled-back, changed, cross-namespace, unknown, and
  store-unavailable learnings, learnings the caller may not read, learnings
  the selected route may not receive, and pins under the template-only
  sanitization contract, are all refused with one non-disclosing
  `FAILED_PRECONDITION: learning pin is unavailable`. A pin is an explicit
  input and is never silently dropped. Namespace authorization runs first, so a
  principal without access to the namespace cannot inject a learning.
- The eval-owned context-expansion gate does not apply. It guards automatic
  retrieval, where the system decides what to add. A pin is explicit, and its
  approval and activation bound to an exact digest are the gate. Rolling the
  learning back disables it immediately for later plans.
- The plan receipt cites the lineage: the learning change ID, the approved
  candidate digest, the verification evidence digest it was bound to, and the
  request it was recorded from. It never copies the learning text.
- SQLite is the reference store, as for learning changes. On the PostgreSQL
  community runtime the store is unavailable, so a pin fails closed.

## Alternatives considered

- Context plus a route suggestion, or plus a tool allowlist. Rejected for this
  change: each moves a trust boundary (routing and egress; capability) and is
  its own decision with its own validation.
- Retrieval without a pin. Rejected: an unpinned learning is not a governed
  input and cannot be cited by digest.
- Requiring the context-expansion eval gate. Rejected: it would make a pin
  unusable until unrelated eval iterations exist, although the activation
  already binds an operator's approval to exact content.
- A prompt-file fallback. Rejected: side files are not the contract.

## Consequences

Operators get one closed loop: verify, record, approve, activate, pin, cite,
roll back. The wire change is additive (`ExecutionInput.learning_pin`,
`ExecutionPlan.learning_references`), so existing callers are unchanged. A
future decision may add route or tool influence without weakening this one.

## Validation

Pure tests cover resolution and every refusal cause. A service test plans twice
and proves the second plan is enriched, keeps the same route and tools, and
cites the lineage on its receipt without copying text. Pipeline tests prove the
egress filter, object authorization, and that routing steps never see the pin.
A process-level test
drives the shipped server and `sekaictl admin learning` through pin, disable,
wrong digest, another namespace, and an unauthorized principal.
