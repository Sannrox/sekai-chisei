# Research freeze: gateway PEP fat-decide surface

Issue: [#163](https://github.com/Sannrox/sekai-chisei/issues/163)  
Date: 2026-07-26  
Status: **recommendation complete — freeze for implementation**

## Decision question

When relocating in-process gateway governance decisions to the control plane,
which control-plane surface should the gateway call **once per request** so the
edge remains a pure policy-enforcement point (PEP)?

## Options compared

| Option | Shape | Fit | Main risk |
| --- | --- | --- | --- |
| **A. Fat decide RPC** | New `DecideGatewayExecution` (name bikeshed OK) returns model route, capability admit, policy/egress, and budget grant in one response | Best match to “one round-trip” | Requires careful response versioning and fail-closed semantics |
| **B. Reuse PlanExecution / ExecutePlan** | Gateway builds a plan and executes it via existing native RPCs | Reuses native client path | Plan/execute is richer than the gateway’s HTTP mapping needs; risk of over-coupling and multi-call sequences |
| **C. Hybrid + local cache** | Fat decide + short-TTL decision cache at the edge | Latency optimization later | Cache correctness/revocation; not day-one |

## Recommendation (freeze)

**Option A — single fat decide RPC**, with Option C deferred.

### Why not PlanExecution first

- Native `PlanExecution` / `ExecutePlan` already serve **agent-native** clients
  with operation graphs, receipts, and multi-step governance.
- The gateway’s job is **HTTP route mapping + enforce + stream**, not to become
  a second plan builder. Reusing PlanExecution would force the gateway to
  synthesize plan IDs, operation classes, and execution envelopes it does not
  own today.
- A dedicated decide surface keeps the gateway crate free of plan/execute
  semantics while still making the control plane the PDP.

### Why not N small RPCs

Today budget is already a separate gRPC hop. Expanding that to
resolve + capability + egress + budget as independent calls multiplies
latency and partial-failure modes. The issue already records this: one fat
call is the mitigation.

### Why cache is later

A decision cache can only be introduced after the fat decide contract is
stable, with explicit TTL, principal binding, and fail-closed invalidation on
policy/credential change. Day-one implementation must be correct without cache.

## Frozen contract shape (implementation target)

### Request (gateway → control plane)

Minimum fields (names illustrative; exact proto in implementation PR):

- `namespace` / caller principal identity (from virtual key / credential)
- requested model / provider hints (as the HTTP client presented them)
- operation class / capability requirements derived from the route
- estimated budget dimensions already used by `CheckBudget`
- request correlation ids (operation / attempt)

### Response (control plane → gateway)

Single decision object:

- **admit** | **deny** with stable reason code (capability, policy, budget, …)
- resolved runtime + model (when admitted)
- budget grant / remaining dimensions needed for post-usage record
- egress / policy markers the edge must enforce (no weaker than today’s
  in-process checks)
- decision / policy version stamps for receipts

### Edge duties after decide

- Map HTTP route → upstream path
- Attach credentials
- **Enforce** admit/deny before any upstream contact
- Forward/stream
- Record usage against the grant
- Assemble gateway-facing errors/receipts from decide + upstream outcome

### Control plane duties

- Model resolution/routing
- Capability check
- Policy / egress decision
- Budget grant
- Audit the decision as a single governed act

## Behavior invariants (non-negotiable)

1. Same input must not become weaker or bypassable after the move.
2. Denial still happens **before** upstream contact.
3. Public OpenAI/Anthropic HTTP contract unchanged.
4. No persistence/migration required for the first cut.
5. Gateway must not re-implement PDP logic “for performance” outside the
   frozen cache follow-up.

## Implementation sequencing

1. **This freeze** (done) — option A locked.
2. **Proto + control-plane decide handler** (landed) — `DecideGatewayExecution`
   RPC + pure compose helpers; deterministic unit tests for admit/deny composition.
3. **Gateway dual-path** (landed, later retired by Issue #418) —
   fail-closed `DecideGatewayExecution`.
   **Deny** refuses upstream; **admit** replaces CheckBudget + ResolvePolicy
   with the PDP response (context egress and health fallback still run at the
   edge). The temporary soft-unavailable fallback was removed by Issue #418.
4. **Canonical path** (landed) — configured gateways always use
   `DecideGatewayExecution`; denial or unavailability fails closed without a
   legacy multi-RPC fallback. Issue #418 completes the decision as
   `gateway.decide/v2`; mixed v1/v2 deployments reject admission during a
   coordinated upgrade.
5. **Optional cache** (Option C) only after production soak of default-on.

## Explicit non-goals of the first slice

- Moving streaming body inspection into the control plane
- Changing Aldunis / tenant / enterprise login ownership
- Full deletion of gateway decision code before parity evidence
- Decision cache

## Conclusion

Freeze **fat decide RPC** as the PDP surface for gateway thinning. Do not
reuse PlanExecution for the HTTP edge. Defer hybrid caching until the fat
contract is live and measured.

No further research is required before implementing step 2 under this freeze.
