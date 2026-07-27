# Research: multi-region consistency for budgets, leases, and permits

Issue: [#292](https://github.com/Sannrox/sekai-chisei/issues/292)  
Related: [#117](https://github.com/Sannrox/sekai-chisei/issues/117) (closed),
[#288](https://github.com/Sannrox/sekai-chisei/issues/288) (closed),
[#293](https://github.com/Sannrox/sekai-chisei/issues/293) (open),
[#294](https://github.com/Sannrox/sekai-chisei/issues/294) (open)  
Date: 2026-07-27  
Status: **recommendation complete**

## Decision question

After replica-safe **single-region** shared state (#117), what consistency model
is acceptable for budgets, coordination leases, and permit redemption **across
regions**—and what must remain single-region-only?

## Product posture

Multi-region is in scope for maximum federation ambition (#288). Exit must
**not** be “defer forever.” A phased topology is acceptable even if v1 is
region-pinned writes only. Fail closed beats availability for spend and permit
double-redeem. SQLite local-first remains valid for single site. No claim of
exactly-once external physical effects.

## Evidence collected (today’s plane)

### Authority model after #117

| Surface | Authority class | Evidence |
| --- | --- | --- |
| Budgets | `shared_store_required` | `src/db/chisei_budget.rs`, `src/db/postgres_budget.rs`, inventory `chisei.budget`, `tests/replica_safety_budget.rs` |
| Leases | `shared_store_required` | `src/sekai/lease.rs`, `src/db/lease.rs`, inventory `sekai.leases`, `tests/replica_safety_leases.rs` |
| Coordination / admission | `shared_store_required` | inventory `sekai.coordination` |
| External-action permits | Durable redeem ledger | `src/chisei/external_permit.rs` (atomic idempotent redeem) |
| Gateway preflight + auto-allocation | Same budget path when wired to control plane | `BudgetTracker` / `check_and_reserve*`; fat-decide and legacy preflight must not invent a second ledger |
| Offline permits | Explicitly **not** global single-use | `docs/external-action-execution.md` (`offline_no_global_single_use`) |

Replica safety covers **multiple processes against one shared store**, not
independent regional stores with lag. `docs/replica-safety.md` lists multi-region
topology as an explicit non-goal of #117.

### Invariants that multi-region must not break

| Object | Current invariant | Failure if two write authorities under lag |
| --- | --- | --- |
| Budget reserve | Atomic check+reserve over scope chain; concurrent reserve cannot overspend shared limit | Split-brain overspend of the same ceiling |
| Budget record | Idempotent markers commit with usage in one transaction | Double-count or lost adjust under dual writers |
| Lease acquire | Single active generation + unique fencing token per key | Dual active owners; fencing collapses |
| Lease takeover | Server clock + observed token/expiry | Clock skew across regions → false “expired” takeovers |
| Permit redeem | Atomic insert keyed by permit + idempotency; restarts re-read durable row | Double-redeem of the same online permit |
| Offline redeem reconciliation | Cap + idempotency; cannot prove disconnected hosts reported every invocation | Already weaker than online; multi-region must not pretend otherwise |

### Failure injections (analytical)

| Injection | Global active/active writers | Region-pinned single writer | Regional budgets + audited transfer |
| --- | --- | --- | --- |
| Network partition between regions | Both sides can reserve/redeem → **overspend / double-redeem** unless a global consensus layer | Pin home continues; peer **fails closed** | Local regional ceilings hold; transfer refuses under partition |
| Clock skew | Lease expiry races; dual takeover | Single writer’s clock is authoritative for that pin | Same as pinned; transfers use audited messages, not wall-clock alone |
| Dual redeem same permit | Succeeds twice without shared ledger | Second region rejects wrong pin / missing home redeem row | N/A (permits not transferred by budget transfer) |
| Auto-allocation under lag | Promote thrash / dual spend | Allocation stays **intra-plane / intra-pin** (#288) | Uses same reserve path as gateway preflight against home scope |
| SQLite local-first single site | Still works only if multi-region mode **off** | Pin = sole site; zero cross-region traffic | `single_region` topology mode |

### Cost of topologies

| Topology | Ops cost | Local-first SQLite | Blast radius | Fit to #288 |
| --- | --- | --- | --- | --- |
| Active/passive DR only | Low | Yes (primary site) | One active site | Incomplete forever-exit |
| Active/active strongly consistent global partition | High (consensus latency, HA of the consensus store) | **No** as complete baseline | Single global write plane | **Rejected** in #288 option 3 |
| Regional budgets + transfer; leases/permits pinned | Medium (transfer is rare admin path) | Yes per region | Bounded to pin/scope home | Aligns with hybrid write authorities |
| Hybrid with explicit class per object type | Medium; clarity tax | Yes | Per-class | **Recommended** |

## Options (from #292)

| # | Option | Verdict |
| --- | --- | --- |
| 1 | Active/passive DR only; no multi-region writes | **Phase 0 posture**, not the architecture exit |
| 2 | Active/active with strongly consistent global budget partition | **Reject** |
| 3 | Regional budgets with explicit transfer; leases/permits region-pinned | **Core of v1 multi-region** |
| 4 | Hybrid with documented consistency class per object type | **Recommend** (includes 3 + freeze for other objects) |

Option 2 is rejected because it:

- breaks the community SQLite single-site baseline as a first-class topology;
- creates one global blast radius for spend and coordination;
- contradicts #288 (“one plane = one write authority”; no global SC control plane).

Option 1 alone is rejected as a **terminal** answer: product requires a phased
path toward multi-region federation ambition. DR-only remains the correct
**default deployment** until operators opt into multi-region modes.

## Recommendation

Adopt a **hybrid, object-typed consistency model**:

1. **Default deployment** remains single-region (SQLite file or one regional
   PostgreSQL). Multi-replica within that region uses #117 shared-store rules.
2. **Leases and online permit redemption** are **region/site-pinned single
   writers** (#293). Cross-region refresh, takeover, or redeem **fails closed**
   unless an explicit, audited handoff protocol later defines a new pin.
3. **Budgets** use **single writer per scope**, with topology modes (#294):
   - `single_region` (default): today’s chain reserve against one store;
   - `regional_with_transfer`: each regional scope has a home pin; org-wide
     ceilings move only via audited transfer/reconcile; under partition, refuse
     debits that cannot prove the combined ceiling (no optimistic dual reserve).
4. **Never** ship a default “global strongly consistent budget partition” that
   requires multi-region consensus for every gateway preflight.
5. **Auto-allocation and gateway preflight** must call the **same** budget
   authority as PlanExecution (`BudgetTracker` / shared store APIs)—no
   process-local or region-shadow ledger for durable spend decisions.
6. **External physical effects** remain at-least-once with evidence; multi-region
   pins do not create exactly-once side effects.

### Consistency class per object type (freeze)

| Object type | Consistency class | Multi-region write | Cross-region allowed operations | Fail-closed requirement |
| --- | --- | --- | --- | --- |
| Coordination leases | `region_pinned_single_writer` | Only at pin | Handoff (future, optional) or deny | No dual active generation under lag |
| Online permit redemption | `region_pinned_single_writer` | Redeem ledger only at pin | Deny redeem at foreign pin | No double-redeem of one online permit |
| Offline permit reconciliation | `pin_home_reconcile_only` | Reconcile at home pin when online | Deny foreign reconcile as authority | Cap + idempotency; never claim global single-use |
| Budget scope (metric + scope_id) | `single_writer_per_scope` | Home pin or explicit transfer lock | Audited transfer of ceiling/usage between homes | No overspend of combined ceiling under partition |
| Graph / ontology mutations | `plane_local_write` (#288) | One control plane | Verify/import only | No remote mutate without attestation path |
| Gunshi auto-dispatch | `intra_plane` (#288/#279) | Local promote only | Import scorecards as evidence, not remote promote | No cross-site auto under lag |
| Provider residency tags | `policy_pin` (#289) | N/A (decision, not durable ledger) | Evaluate before upstream | Deny illegal region/data class |

### Topology modes (operator-visible)

| Mode | Budgets | Leases / permits | When to use |
| --- | --- | --- | --- |
| `single_region` (default) | Shared store as today | Pin optional/constant local site id | Community SQLite, single AZ/region PG |
| `regional_pinned` | Per-region scopes; no automatic global ceiling | Mandatory pins; foreign pin fail closed | Multi-region without shared spend pool |
| `regional_with_transfer` | Regional homes + audited transfer for pooled ceilings | Same pins as `regional_pinned` | Multi-region org with rare reallocation |

`active_active_global_sc` is **not** a supported mode.

### Handoff (leases/permits) — design note for #293

v1 may ship **without** handoff: pin is permanent for the lease key / permit
lifetime; operators drain work in-region. If handoff is added later, it must:

- be an explicit RPC/admin path (not silent redirect);
- audit old pin, new pin, actor, and generation/permit ids;
- serialize so the old pin refuses further redeem/refresh before the new pin
  accepts;
- never allow both pins to accept concurrent redeem or acquire.

### Budget transfer (design note for #294)

Transfer is **not** a distributed two-phase debit of live request traffic. It is
a rare, audited movement of limit and/or reserved capacity between scope homes:

- both homes durable; transfer id idempotent;
- under partition, open transfers do not authorize overspend on either side;
- gateway and Gunshi never implement a second transfer path.

## Phased Feature Issues (already opened)

No new Issues are required. Implement against this freeze:

| Order | Issue | Outcome under this freeze |
| --- | --- | --- |
| 1 | **#293** region-pinned leases and permit redemption | Persist `site_id`/`region` pin on lease records and online redeem rows; foreign pin fail closed; dual-region (or simulated) test that double redeem / dual acquire fails; receipts/evidence expose pin; document handoff as non-goal for v1 or specify the protocol above |
| 2 | **#294** multi-region budget topology | Document and implement topology modes; partition test: cannot overspend combined ceiling; transfer/reconcile audited if `regional_with_transfer`; operator pressure views may show regional vs global **only when** topology exposes both; auto-allocation and gateway preflight share `BudgetTracker` authority |

**Preferred sequencing:** land **#293** before or concurrent with **#294**. Budget
topology that assumes multi-region without pinned coordination will re-open
double-redeem and dual-lease races under the same lag model.

### Acceptance anchors for implementers

**#293**

- Fixture or harness: two logical regions, one permit → second redeem fails.
- Fixture: two regions, same lease key → second acquire/refresh fails closed.
- Pin visible on lease get / redeem evidence attributes.
- Single-region deployments keep working (constant pin or topology
  `single_region`).

**#294**

- Topology mode is explicit in config/docs; default `single_region`.
- Partition test for pooled ceiling under `regional_with_transfer`.
- No silent global SC mode.
- Same authority path for preflight and execution reserve.

## Explicit non-actions

- Do not implement multi-region consensus for every budget preflight.
- Do not treat offline permits as multi-region exactly-once authority.
- Do not allow Gunshi auto-dispatch or remote promote across region pins.
- Do not merge tenancy or write graphs across control planes (#291 remains
  verify/import federation, not shared mutability).
- Do not claim external side effects are exactly-once because pins exist.

## Relationship to #288

#288 recommended regional write authorities + verify-only federation and left
#292 as the gate before multi-region lease/budget features. This document
**closes that gate** with object-typed classes and points implementation at
existing #293 and #294.

## Conclusion

**Recommend hybrid option 4**, built on **region-pinned leases/permits** and
**single-writer budget scopes with optional audited transfer** (option 3), with
**active/passive DR as the default single-region deployment**, and **reject
global strongly consistent active/active** for these ledgers. Consistency
classes above are the design freeze for #293 and #294.
