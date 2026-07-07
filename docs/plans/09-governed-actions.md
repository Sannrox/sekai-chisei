# Plan 9: Governed actions & tool-use

> **Status: implemented.** All four phases (A–D) landed. Action policy,
> approval holds, blast-radius caps, action-class budgets, and the tool-use
> bridge are enforced at the `ExecuteAction` boundary and audited. See
> "Implementation" below.

**Goal.** Extend chisei's governance from *tokens, models, and data egress* to
the **effects agents produce** — the tool calls and graph mutations they make.
Today the gateway governs the model *call*; nothing governs what the agent then
*does* with the answer. That's where real-world blast radius lives.

**Why now.** It's the biggest unhedged risk after 6–8: we meter and route
traffic but don't gate side effects. It's a direct extension of existing
machinery (see below), independently valuable regardless of the cost work, and a
prerequisite for ever letting the self-improvement loop (Plan 11) change behavior
autonomously.

## Current seeds in code

- **Sekai already has a governed action system.** `src/sekai/action.rs`:
  `ActionExecutor`, `ActionTypeDef` (name + params + `ops`), `ActionOp` (typed
  graph ops like `create_object`/`delete_link`), registration/validation, and
  authorized execute targets (#26, #40). So actions are *typed and executable*;
  what's missing is a *policy/approval/budget* layer around them.
- **The gateway audit + egress path** (`RecordGatewayAudit`, `apply_context_egress`,
  `gateway.rs`) already models "decide, record, allow/deny" — the same shape an
  action gate needs.
- **Work-unit attribution** (`X_CHISEI_WORK_UNIT`/`X_CHISEI_TASK_ID`, `gateway.rs:43`)
  gives actions a task to attribute to.

## Phases

**A — Action policy.** A per-namespace/per-agent policy over action types and
ops: allow / deny / require-approval, mirroring the namespace model policy. Ops
carry a risk class (read vs write vs destructive — `delete_link` is already
special-cased in `action.rs`). Deny/allow decisions flow through
`RecordGatewayAudit` like egress does.

**B — Approval gate.** For `require-approval` actions, hold execution and surface
an approval request (audited, with the proposing agent, work-unit, and the exact
op payload). Approve/deny out-of-band; resume or drop. Dry-run mode that reports
the ops an action *would* perform without executing.

**C — Action budgets & blast-radius.** Rate/volume limits per action class
(reuse the budget machinery: `chisei/budget.rs`, `SetBudgetLimit`), plus
blast-radius caps (e.g. max objects mutated / links deleted per work-unit) that
hard-stop runaway loops. Ties into the guardrail idea from Plan 8.

**D — Tool-use bridge (the LLM connection).** Map model tool-calls to governed
Sekai actions so an agent's tool call is policy-checked, budgeted, and audited
before it executes. Two options to evaluate: (1) govern at the `ActionExecutor`
boundary (client executes tools by calling Sekai actions — already the trust
boundary); or (2) inspect tool-use blocks in the Messages/Responses stream at the
gateway. Prefer (1): it's the real enforcement point and doesn't require parsing
provider-specific tool formats.

## Risks / open questions

- Enforcement point: gateway-side stream inspection is brittle (per-provider tool
  formats); the `ActionExecutor` boundary is the sound place. Confirm all
  effectful paths funnel through it.
- Approval UX/transport is undefined — start with audited hold + CLI approve.
- Don't double-govern: reads already covered by egress; this plan is about
  writes/effects.

## Dependencies

Independent of 7/8, but shares the audit path. Precedes Plan 11 (autonomous
behavior change is only safe once effects are governed).

## Commit style

`feat(sekai)` for action policy/executor changes, `feat(chisei)` for
budget/blast-radius, `feat(gateway)` if a stream-side hook lands.

## Implementation

Enforcement lives entirely at the `ExecuteAction` gRPC boundary
(`src/grpc/sekai_service.rs`), the single trust boundary for graph effects.

- **Risk classification** (`src/sekai/action.rs`): `RiskClass`
  (`Read` < `Write` < `Destructive`); ops map to a class (`delete_link` /
  `delete_object` = destructive, others = write, unknown = destructive/fail-safe);
  an action type's class is the max over its ops.
- **Action policy** (`src/sekai/action_policy.rs`): `ActionPolicy` stored as a
  Sekai object of kind `action_policy` (`external_id = action_policy:{scope}`),
  mirroring the namespace model policy. Decision precedence: per-action override
  → per-risk-class override → scope default. Scope resolution is
  **agent-then-namespace** (`agent:<actor>`, then the object namespace). No
  policy == allow (backward compatible). RPCs: `SetActionPolicy` /
  `GetActionPolicy` / `ListActionPolicies` (behind `check_action_admin`).
- **Enforcement + audit**: after per-target `check_write`, the gate resolves the
  policy, computes risk, and decides. `deny` → `PermissionDenied` +
  `action_policy_denied` audit row. All decisions flow through the existing
  `record_decision` audit path with `risk_class` / `policy_scope` / `decision`
  evidence.
- **Dry-run**: `ExecuteActionRequest.dry_run` returns the planned ops and the
  resolved decision without mutating or erroring; audited as
  `execute_action_dry_run`.
- **Approval hold (Phase B)** (`src/sekai/action_approval.rs`): `require_approval`
  persists an `action_approval` object (proposing actor, work-unit from
  `x-chisei-work-unit`/`x-chisei-task-id`, exact params for resume, sensitive
  values redacted on display) and returns a pending result. `ApproveAction`
  re-checks policy + `check_write` at execution time before resuming;
  `DenyAction` drops it; `ListPendingApprovals` lists holds. All transitions
  audited.
- **Blast-radius caps (Phase C)**: per-work-unit mutation/delete counters
  (`action_blast_radius` objects) hard-stop with `ResourceExhausted` +
  `action_blast_radius_exceeded` audit when a policy cap would be exceeded.
- **Action-class budgets (Phase C)**: `ExecuteAction` shares chisei's
  `BudgetTracker` and meters each executed action against subject
  `action:<risk_class>` (checked before, recorded after); exhaustion →
  `ResourceExhausted` + `action_budget_exceeded`. Set limits via chisei
  `SetBudgetLimit` on that subject.
- **Tool-use bridge (Phase D)** (`src/sekai/tool_bridge.rs`): `ToolCall` maps a
  provider-agnostic model tool-call to `ExecuteAction` params. The client runs
  tools by calling `ExecuteAction`, so tool-calls are policy-checked, budgeted,
  and audited. See `examples/governed_tool_use.rs`.

**CLI**: `sekaictl action policy set|get|list` and
`sekaictl action approvals list|approve|deny`.

**Enforcement caveat**: only `ExecuteAction` is action-policy-governed. The
lower-level CRUD RPCs (`CreateObject`, `UpdateObject`, `DeleteObject`,
`CreateLink`, `DeleteLink`) remain governed by object-level access control and
audit but bypass the action-policy/approval/budget/blast-radius layer. Agents
must route effectful tool-calls through `ExecuteAction` to be governed.
