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
5. Bind one issued `AllocationPlan` on `PlanExecution` when a durable
   `gunshi.recommendation_issued` row already exists. There is no public
   issuance RPC. Local `sekaictl admin governance gunshi recommend` writes
   advisory JSON only.
6. **Kill switch** or **rollback** to return to advisory / prior revision.

Promotion enforces a 60s cooldown per namespace to reduce thrash.

## Native planning integration

Gunshi is the outer allocation stage for fleet-managed native operations. It
does not replace Chisei planning or execute provider calls:

```text
in-process record_issued_recommendations
  -> durable gunshi.recommendation_issued rows
  -> bind one issued AllocationPlan to PlanExecution
  -> Kioku and the remaining per-operation planning steps
  -> ExecutePlanStream
  -> operation receipt and Gunshi feedback
```

Send the issuance id and the exact issued `AllocationPlan` JSON in
`PlanExecutionRequest.gunshi_allocation`. Chisei reloads the durable issuance
and rejects changed JSON, stale policy versions, namespace or operation
conflicts, mismatched priorities or tools, caller route conflicts, and live
runtime/model resolution that no longer matches the allocation. There is no
public issuance RPC; a local recommend bundle cannot satisfy this bind.

The resulting plan and receipt retain Gunshi's allocation id, agent, policy
version, input fingerprint, budget ceiling, maximum attempts, and human-review
requirement. The native plan id remains the receipt id; the allocated operation
is recorded as `logical_operation_id` and is used to validate later outcome
feedback.

Kioku participates at two distinct scopes: Gunshi may consult governed outcome
evidence while choosing fleet resources, and `PlanExecution` still runs Kioku
as per-operation context enrichment after allocation. Automatic dispatch is
evaluated from durable `gunshi_auto` policy, calibration scorecard, capacity
envelope, and residency policy. See
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

## CLI and console

```text
sekaictl admin governance gunshi recommend <input.json> --output <recommendations.json>
```

Install, promote, opt-in, kill switch, rollback, and status live on the
operator console Gunshi tiles. They call `gunshi_auto` in-process.

## Feedback → eval suites (#300)

Authorized operator choices can be promoted into append-only suites whose ids
start with `feedback-`. Case ids are deterministic from
`(issuance_id, allocation_id)` so promotion is idempotent. Operator rationale is
redacted in the stored case spec; promotion is audited. API clients submit
feedback and promote it through the Gunshi auto-allocation store; these
lifecycle mutations do not need dedicated RPCs.

## Persistence

SQLite table `chisei_gunshi_allocation_state` and its PostgreSQL counterpart store
the durable control blob with revision CAS. Mutations also emit audit decisions under
`gunshi.allocation_policy.*`.
