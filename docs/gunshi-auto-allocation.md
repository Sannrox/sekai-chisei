# Gunshi eval-gated promotion and bounded auto-dispatch

Issue: [#280](https://github.com/Sannrox/sekai-chisei/issues/280)  
Envelope research: [279-gunshi-auto-allocation-envelope.md](research/279-gunshi-auto-allocation-envelope.md)

## Default posture

| Control | Default |
| --- | --- |
| Namespace allocation policy | None until an operator installs a baseline |
| Auto-dispatch | **Off** (advisory only) |
| Namespace opt-in | Required after a promoted revision with `dispatch.enabled=true` |
| Kill switch | Off; when on, forces advisory and clears opt-in |
| Default-on auto | **Forbidden** |

## Operator flow

1. **Install baseline** — advisory revision (`dispatch.enabled=false`) + evaluation gate.
2. Collect advisory outcomes and suite evaluations with attributable evidence.
3. **Promote** a candidate revision when the gate passes (CAS on `expected_revision`).
4. **Opt in** the namespace to live auto-dispatch.
5. Read the aligned auto-dispatch decision and receipt attributes returned by
   **IssueGunshiRecommendations** before dispatching.
6. **Kill switch** or **rollback** to return to advisory / prior revision.

Promotion enforces a 60s cooldown per namespace to reduce thrash.

## Native planning integration

Gunshi is the outer allocation stage for fleet-managed native operations. It
does not replace Chisei planning or execute provider calls:

```text
IssueGunshiRecommendations
  -> allocation plans + aligned dispatch decisions and receipt attributes
  -> bind one issued AllocationPlan to PlanExecution
  -> Kioku and the remaining per-operation planning steps
  -> ExecutePlanStream
  -> operation receipt and Gunshi feedback
```

Send the issuance id and the exact issued `AllocationPlan` JSON in
`PlanExecutionRequest.gunshi_allocation`. Chisei reloads the durable issuance
and rejects changed JSON, stale policy versions, namespace or operation
conflicts, mismatched priorities or tools, caller route conflicts, and live
runtime/model resolution that no longer matches the allocation.

The resulting plan and receipt retain Gunshi's allocation id, agent, policy
version, input fingerprint, budget ceiling, maximum attempts, and human-review
requirement. The native plan id remains the receipt id; the allocated operation
is recorded as `logical_operation_id` and is used to validate later outcome
feedback.

Kioku participates at two distinct scopes: Gunshi may consult governed outcome
evidence while choosing fleet resources, and `PlanExecution` still runs Kioku
as per-operation context enrichment after allocation. Automatic dispatch is
evaluated during issuance against the durable allocation policy, calibration
scorecard, capacity envelope, and residency policy. See
[ADR 0015](decisions/0015-gunshi-allocation-precedes-native-planning.md).

## Receipt attributes (auto path)

When authorization succeeds, receipt attributes include:

- `auto_dispatch=true`
- `gunshi_allocation_id`
- `allocation_policy_revision`
- `dispatch_policy_id` / `dispatch_policy_version`
- `promotion_gate_id` / `gate_version`
- `dispatch_mode=automatic`

Denials set `auto_dispatch=false` and `dispatch_denial_reasons`.

## Hard limits (cannot relax under auto)

- Approval / human review requirements
- Privacy / egress hard limits at promotion
- Operation risk above `Low`
- Tool set must match required tools exactly
- Budget may only decrease within envelopes
- Namespace and operation-class allow-lists are explicit (no `*`)

## CLI

```text
sekaictl admin governance gunshi install-baseline --namespace <ns> --snapshot <json> --gate <json>
sekaictl admin governance gunshi promote --namespace <ns> --candidate <json> --baseline-eval <json> --candidate-eval <json> --expected-revision <id>
sekaictl admin governance gunshi auto-opt-in --namespace <ns> --expected-revision <id>
sekaictl admin governance gunshi kill-switch --namespace <ns> --reason <text>
sekaictl admin governance gunshi rollback --namespace <ns> --expected-revision <id> --reason <text>
sekaictl admin governance gunshi allocation-status --namespace <ns>
```

## Feedback → eval suites (#300)

Authorized operator choices can be promoted into append-only suites whose ids
start with `feedback-`. Case ids are deterministic from
`(issuance_id, allocation_id)` so promotion is idempotent. Operator rationale is
redacted in the stored case spec; promotion is audited. API clients submit
feedback and promote it through the `feedback` and `promote_feedback`
operations of `SetGunshiAllocationPolicy`; these lifecycle mutations do not
need dedicated RPCs.

## Persistence

SQLite table `chisei_gunshi_allocation_state` stores the durable control blob with
revision CAS. PostgreSQL community runtime returns unavailable for these methods
until parity is added. Mutations also emit audit decisions under
`gunshi.allocation_policy.*`.
