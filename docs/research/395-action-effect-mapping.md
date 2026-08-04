# Research: map Action/Effect onto operations, work units, permits, and evidence

Issue: [#395](https://github.com/Sannrox/sekai-chisei/issues/395)  
Date: 2026-07-27  
Status: **recommendation complete**  
Follow-ups: existing #396–#401 (re-grounded below); no Design Discussion required for the mapping freeze if follow-ups stay additive and respect boundaries in this document.

## Decision question

How should a **generic Action layer** (decision unit + typed effects + runtime
claim) map onto existing sekai-chisei concepts—operations, work units,
coordination/admission, external evidence, permits/redemption, and
harvest/receipts—**without creating a second system of record**, while enabling:

```text
incoming evidence / admission → durable decision → outgoing runtime placement
```

Core contracts must stay **domain-neutral** (no GitHub- or product-specific
types in the plane).

## Maintainer constraints (from #395)

| Constraint | Implication |
| --- | --- |
| Plane is governance + durable operational SoR | Must not become an agent process runner |
| Domain producers are adapters | Core types are abstract; adapters own webhook/VCS shapes |
| Runtime hosts claim work and harvest | Hosts do not own admission policy |
| External mutations stay permit/host-executor | Free-form model tools are not the write path |
| Dual-backend + inventory rules | New surfaces need SQLite evidence; Postgres fail-closed until parity |
| Compatibility | Prefer additive RPCs |

## Evidence collected

### A. Vocabulary that already exists (collision map)

| Existing term | What it is today | Service |
| --- | --- | --- |
| **Graph Action** (`ExecuteAction`, `ListActionTypes`, …) | In-process **graph mutation DSL** (ops: `set_property`, `create_object`, …) with policy/approval | Sekai |
| **Operation** (`PlanExecution` / `ExecutePlanStream`, `ReportOperationEvent`, `GetOperationReceipt`) | **Correlation spine** for a governed run: plan → execute → events → receipt | Chisei |
| **Work unit** (`CreateWorkUnit`, `TryAdmitWorkUnit`, heartbeat/complete/fail) | **Capacity / contention** primitive (scopes, FIFO admission, leases on reservations) | Sekai |
| **Evidence** (`SubmitEvidence`, schemas, lifecycle projection) | **Observation funnel** for admitted external facts | Sekai |
| **External-action permit** (`AuthorizeExternalAction` → issue/verify/redeem) | **Bounded host mutation authority**; separate from “did it run” evidence | Chisei |
| **External-action execution evidence** | Host lifecycle observations via evidence type `external_action_execution` | Docs + evidence funnel |

**Critical collision:** the proposed “Action layer” in #396–#401 is **not** the
graph `ExecuteAction` family. Implementation Issues and protos must use a
distinct name on the wire and in docs (recommendation: **`ActionInstance`** /
product phrase **governed action instance**). Graph Action stays as graph DSL.

### B. RPC inventory (relevant clusters)

**Sekai — coordination**

- Work units: create/get/list, try-admit, heartbeat, complete, fail, cancel,
  reconcile
- Reservations: list and reconciliation
- Leases: acquire/get/refresh/release/takeover (generation fencing; object-bound
  keys)

**Sekai — graph Action (do not overload)**

- Action type CRUD, `ExecuteAction`, action policy, approve/deny

**Sekai — evidence**

- Register producer/schema, submit/batch, get/list content, replay, retract,
  mark stale

**Chisei — operation spine**

- `PlanExecution`, `ExecutePlanStream`, `ReportOperationEvent`,
  namespace grants, `GetOperationReceipt`, statistics

**Chisei — external mutation**

- Authorize → approve/cancel → issue/verify/redeem/revoke/delegate permit,
  kill-switch, permit policy

**Gateway**

- Host-initiated HTTP/alias path; claim of gateway aliases is **not** the
  product “runtime claim” for admitted plane work (#399).

### C. Where “plane-initiated start” is missing

Today’s governed agent path is effectively **host-initiated**:

```text
client/host → PlanExecution → ExecutePlanStream → tools/authz → ReportOperationEvent / harvest
```

What is **not** first-class:

1. A durable, typed **decision unit** admitted by the plane with idempotency
   before any host run starts.
2. A **claim** API for admitted outbound placement (`runtime_dispatch`) so a
   runtime host pulls work the plane already accepted.
3. A clean link from **evidence admission** → **decision admit** without
   encoding domain webhook schemas in core.

Work-unit `TryAdmitWorkUnit` is capacity admission, not “this decision type is
policy-approved with typed effects.” External permits authorize mutations; they
do not schedule runtime turns.

### D. Option evaluation

| # | Option | Verdict | Why |
| --- | --- | --- | --- |
| 1 | Action = operation | **Partial accept** | Operation is the right **correlation/receipt spine**, but plan/execute today is host-driven and LLM-plan shaped. Overloading operation attributes alone is too loose for type registry + typed effects (#396 alternatives). |
| 2 | Action = work unit | **Reject** | Work units are contention/capacity. Making them decision identity conflates quota scopes with decision types and breaks multi-effect decisions. |
| 3 | Action is new first-class object | **Accept with strict bindings** | Needed for type version, idempotent admit, effect list, and claim keys. Dual-SoR risk is real **unless** execution progress and harvest stay on existing surfaces. |
| 4 | Effects-only (no decision type) | **Reject** | Cannot fail closed on unknown types; no durable admit identity; claim and budget attach nowhere stable. |

## Recommendation (chosen mapping)

### One sentence

Introduce an **`ActionInstance`** as a **thin durable admission envelope** that
**binds** to an **`operation_id`** for receipts/harvest, may **optionally** use
**work units** for capacity, takes **evidence submission ids** as inputs, emits
**typed effects** as children, and routes external mutations through the
**existing permit** path—never a second execution SoR.

### Mapping table

| New concept | Maps to / binds | Does **not** replace |
| --- | --- | --- |
| **Action type** (namespace-scoped registry) | **New** durable definition: id+version, parameter schema, allowed effect kinds, policy/budget hooks | Graph `ActionType` / `ExecuteAction` ops |
| **ActionInstance** (decision unit) | **New** durable record; at admit time allocates/binds **`operation_id`** used for `ReportOperationEvent` / `GetOperationReceipt` | Operation plan IR, work-unit identity |
| **Effect** (`runtime_dispatch`, `notify`, …) | **Children** of ActionInstance; ordered, typed, immutable after admit (except explicit cancel/disable of pending effects) | Free-form tool strings as authority |
| **Claim** (runtime host pull) | **New** claim/lease RPC over **admitted `runtime_dispatch` effects** (fencing + idempotency) | `TryAdmitWorkUnit` as sole claim API; gateway alias claim |
| **Work unit** | **Optional capacity instrument** when contention scopes apply to a dispatch effect | Decision identity |
| **Evidence submission** | **Input linkage** (0..N submission ids); observation-only path may stop at evidence | Decision admit (requires explicit submit) |
| **External mutation** | Effect kind or post-claim host path that uses **AuthorizeExternalAction / permits / redeem** + execution evidence | New parallel permit stack |
| **Harvest / receipt** | Existing **operation event + receipt** pipeline keyed by bound `operation_id` | Parallel harvest store on ActionInstance |

### Lifecycle (normative sketch)

```text
(a) Observation-only
  adapter → SubmitEvidence → admitted evidence
  (no ActionInstance unless a later submit references those submissions)

(b) Admitted work
  adapter/principal → SubmitActionInstance
       (type+version, params, idempotency key+digest, optional evidence links)
    → plane: authz + policy + budget → durable ActionInstance + operation_id
    → materialize effects
         runtime_dispatch → claimable placement (host Claim → run → harvest to operation_id)
         notify → plane-side notification delivery (no host claim)
         (external_mutate) → existing permit authorize/issue/redeem path
```

Plane **never** runs agent turns. Hosts **claim** dispatch effects; they
**report** via existing operation reporter/receipt rules.

### Naming freeze

| Layer | Name |
| --- | --- |
| Graph mutation DSL | keep **Action** / `ExecuteAction` (unchanged) |
| Decision / admission layer | **ActionInstance** + **ActionType** (registry) in Issues/docs; wire package names must not collide with graph Action messages (e.g. `GovernedActionType`, `SubmitActionInstance`) |
| Product speech | “governed action instance” when ambiguity with graph Action matters |

Follow-up Issues #396–#401 may keep short titles (“Action type registry”) but
implementation PRs must use non-colliding proto identifiers.

### Explicit non-goals (what Action is *not*)

- Not an agent process runner or turn engine.
- Not a replacement for graph `ExecuteAction`.
- Not a second receipt/harvest store (operations remain the harvest spine).
- Not a second permit system (external mutations stay on external-action path).
- Not work-unit identity (work units remain capacity).
- Not domain webhook schemas or GitHub issue types in core.
- Not a workflow/BPMN engine or condition auto-submit (later tracks).
- Not offline FS queues as the long-term product path (interim host bridges only).

### Dual-SoR avoidance rules (must ship with first feature PR)

1. **Single correlation id:** every ActionInstance has exactly one bound
   `operation_id` used for receipts; do not invent `action_receipt` tables that
   duplicate operation receipts.
2. **Single mutation authority path:** host side effects that mutate external
   systems go through permits + execution evidence; ActionInstance only records
   the decision and effect intent.
3. **Claim leases ≠ graph leases:** claim fencing may reuse lease *patterns*
   but must not overload object-bound graph lease keys without an explicit
   design note in the claim Issue.
4. **Idempotency lives on submit:** admit key+digest on ActionInstance; effect
   claim has its own request_id; do not require clients to invent two competing
   “primary” keys.

## Design Discussion?

| Question | Answer |
| --- | --- |
| Is a Design Discussion required before **any** feature work? | **No**, if this freeze is accepted and #396–#401 stay additive under the mapping above. |
| When would Discussion be required? | Hard rename/delete of graph Action or operation RPCs; changing receipt SoR; or making the plane execute agent turns. |
| Pre-1.0 public additive RPCs | Labeled feature Issues + inventory + dual-backend rules are enough. |

## Follow-up Issues (existing stack, re-grounded)

Already opened; **do not recreate**. After this freeze lands, advance labels:

| Issue | Role under this freeze | Ready when |
| --- | --- | --- |
| **#396** Action type registry | Namespace-scoped **governed** action type registry (not graph ActionType) | This freeze |
| **#397** submit/admit instances | Create ActionInstance + bind `operation_id` + idempotency | #396 |
| **#398** typed effects | Children: at least `runtime_dispatch` + `notify`; external mutate via permit path | #397 |
| **#399** runtime claim API | Claim admitted `runtime_dispatch` effects; multi-host safe | #398 |
| **#400** harvest/receipts binding | Wire harvest to bound `operation_id`; no parallel receipt SoR | #397 + #399 |
| **#401** external evidence producer contract | Thin producer contract for adapters that later submit ActionInstances | #397 |

**Suggested implementation order:** 396 → 397 → 398 → 399 → 400; 401 can
parallelize after 397 (producer contract) once admit exists.

### Optional later (not blocking this track)

- Collapse external permit RPC family (#383 S6) remains independent shrink work.
- Graph Action demotion/tiering is orthogonal (#383 product_tier).
- Shikigami plane-intake consumer Issues stay blocked until #399 exists (or use
  a documented temporary FS bridge only).

## Exit artifacts

| Artifact | Status |
| --- | --- |
| This freeze | `docs/research/395-action-effect-mapping.md` |
| Mapping table + non-goals | above |
| Follow-up Issues | #396–#401 already shaped; re-label after land |
| Design Discussion | not required for mapping |

## Recommendation summary

**Reject** identifying Action with work units or effects-only. **Accept** a new
**ActionInstance** admission envelope that **binds the existing operation
receipt spine**, uses **work units only for capacity**, feeds on **evidence**,
places work via **claimable typed effects**, and keeps **external permits** as
the mutation authority path. Distinguish hard from graph **`ExecuteAction`**.
This unblocks #396 without dual systems of record.
