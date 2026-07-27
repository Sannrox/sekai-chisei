# Research: safe envelope for Gunshi auto-allocation

Issue: [#279](https://github.com/Sannrox/sekai-chisei/issues/279)
Follow-up feature: [#280](https://github.com/Sannrox/sekai-chisei/issues/280)
Date: 2026-07-26
Status: **recommendation complete**
Operator guide: [gunshi-auto-allocation.md](../gunshi-auto-allocation.md)

## Decision question

What is the minimum safe envelope for Chisei to auto-apply Gunshi
recommendations without operator accept-per-call, while remaining fail-closed
and inspectable?

## Evidence collected (code)

| Area | Location | What exists today |
| --- | --- | --- |
| Advisory allocation | `src/chisei/gunshi.rs` | `recommend_advisory`, allocation contracts, risk ladder |
| Auto-dispatch authz | `src/chisei/gunshi_dispatch.rs` | `AutoDispatchPolicy`, `authorize_dispatch`, `DispatchMode::{AdvisoryOnly,Automatic}` |
| Feedback / calibration | `src/chisei/gunshi_feedback.rs` | operator choice, outcomes, advisory scorecards |
| Eval-gated policy | `src/chisei/gunshi_policy.rs` | promote / retain / rollback with `PolicyEvaluationGate` |
| Execution shape | `src/chisei/gunshi_optimization.rs` | best-of-n, fallbacks, early stop, human attention |

### Hard limits already enforced by `authorize_dispatch`

Auto-dispatch is **denied** (falls back to advisory) when any of:

1. `policy.enabled == false` (per-policy kill)
2. Namespace or operation class not on explicit allow-lists (no `*`)
3. Operation risk > `Low` (validated: only Low is legal on the policy)
4. Human approval / review required on the pending operation or plan
5. Budget or attempt ceilings exceed policy, capacity, or operation envelopes
6. Selected tools do not **exactly** match required tools
7. Selected agent is unhealthy / insufficient slots / model not allowed
8. Governed Kioku evidence missing when required
9. Advisory calibration below min comparisons, outcomes, or acceptance rate
10. Governance policy version mismatch across plan / capacity / dispatch

These map cleanly to option **(2) axis allow-list** and option **(1) kill + advisory default**.

### Promotion path already present

`apply_promotion` in `gunshi_policy.rs` requires:

- Hard-limit checks (policy, security, privacy, approval, budget, capacity)
- Sample floors and success / acceptance / quality floors
- Cost and latency regression bounds vs baseline
- Attributable evidence references
- Stored rollback snapshot + baseline evaluation for reverse

This is option **(1)** eval-gated promotion of a named revision.

## Failure modes considered

| Mode | Mitigation in envelope |
| --- | --- |
| Thrash (flip-flop promote/rollback) | Gate requires min samples; retain is default; cooldown on promote (require in #280) |
| Budget oscillation | Auto-dispatch re-checks live capacity budget; promotion monitors cost/success |
| Approval bypass | Auto path refuses any op with `approval_required` or human review |
| Egress / privacy relax | Not an optimization axis; hard_limits.privacy must pass at promote |
| Provider flapping (#162) | Health checked via agent.healthy + live capacity; auto must not override failover |
| Silent auto path | Receipts must carry `auto_dispatch`, policy revision, recommendation id |

## Recommendation (freeze for #280)

**Hybrid of options 1 + 2 + 4**, not progressive autonomy timers (option 3) in v1.

### 1. Default posture

| Setting | Value |
| --- | --- |
| Global / namespace default | **Advisory only** (`AutoDispatchPolicy.enabled = false`) |
| Auto-dispatch | **Namespace opt-in** after a promoted revision is installed |
| Default-on auto | **Forbidden** without an explicit Design Discussion (matches #280) |

### 2. Promotable axes (may change under auto-dispatch)

Within the promoted revision and live capacity envelopes only:

| Axis | Auto-allowed? | Notes |
| --- | --- | --- |
| Model / runtime / agent selection | Yes | Must remain in operation `allowed_models` and agent capability |
| Attempt counts / best-of-n / parallel attempts | Yes | Hard-capped by policy + capacity |
| Fallbacks / early-stop within envelope | Yes | Cannot drop required verification checks |
| Tool set | No change | Must equal `required_tools` exactly |
| Operation risk class | No raise | Auto only for `Low` |
| Approval requirement | **Never relax** | If approval required → advisory |
| Privacy / data-class / egress | **Never relax** | Gate hard_limits.privacy |
| Budget ceiling | May lower only | Never exceed operation or remaining capacity |

### 3. Required eval / promotion evidence shape

Promotion of a candidate revision **must** attach a `PolicyEvaluation` with:

- `policy_revision_id`, `suite_id`, `run_id`
- `samples`, `successful_outcomes`, `operator_acceptances`
- `mean_quality`, `cost_per_success_usd_micros`, `p95_latency_ms`
- `hard_limits` all true
- Non-empty `evidence_references` (attributable, not free-form win-rate)

Gate thresholds live on `PolicyEvaluationGate` (suite-bound). #280 must wire
this to durable storage and namespace-authorized RPCs if not already complete.

### 4. Kill switch + rollback

| Control | Behavior |
| --- | --- |
| Kill switch | Sets dispatch `enabled=false` for the namespace immediately; new ops advisory-only |
| Rollback | Restores prior `AllocationPolicySnapshot` + baseline evaluation via `PolicyTransition::Rollback` |
| Audit | Promote, kill, rollback are privileged mutations with decision records |
| Race safety | Single active revision per namespace; promote/rollback transactional under the runtime backend |

### 5. Receipt contract (auto path)

Every auto-dispatched operation receipt must include attributes:

- `auto_dispatch=true`
- `gunshi_allocation_id` / recommendation id
- `allocation_policy_revision`
- `dispatch_policy_id` + `dispatch_policy_version`
- `promotion_gate_id` + `gate_version` (when installed via promotion)
- Mode distinction: auto vs human-accepted advisory

### 6. Progressive autonomy (deferred)

Shadow → timer → auto is **not** required for #280 v1. Calibration already
uses advisory comparisons + operator acceptance rate. Timers add UX risk
without improving fail-closed posture. Revisit after #280 lands.

## Refined acceptance criteria for #280

Use these as the planning truth for the feature PR:

1. **Promote / fail / rollback** deterministic tests with matching and mismatched evidence (existing pure logic + RPC/CLI wiring).
2. **Auto-dispatch does not run** when opt-in is off, kill switch is active, or calibration floors fail.
3. **Negative tests**: cannot auto-dispatch when approval required, risk > Low, tools differ, budget exceeded, or evidence missing.
4. **Cannot relax** approval / privacy / egress via optimization or dispatch policy validation.
5. **Race-safe** promote/rollback under SQLite (and Postgres when parity exists).
6. **E2E fixture**: outcomes → scorecard → eval → promote → namespace opt-in → authorize_dispatch Automatic → receipt fields present.
7. **Operator-visible status**: active revision, auto on/off, last gate result, kill switch state.

## Explicit non-recommendations

- Do not default auto-dispatch on for any namespace.
- Do not allow wildcards in namespace or operation-class allow-lists.
- Do not treat advisory scorecard alone as promotion evidence (needs suite gate + hard limits).
- Do not expand Gunshi into multi-step agent planning.

## Conclusion

Ship **#280** as: *eval-gated promotion of a revision that embeds an already-strict
`AutoDispatchPolicy` + `OptimizationPolicy`, with namespace opt-in and kill/rollback*.
The safe envelope is largely implemented in pure modules; remaining work is
durable wiring, operator surfaces, receipt fields, and the negative tests above.

No further research is required before implementing #280 under this envelope.
