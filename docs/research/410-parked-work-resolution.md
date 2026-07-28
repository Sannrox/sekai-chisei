# Research: durable parked-work resolution and resumable runtime claims

Issue: [#410](https://github.com/Sannrox/sekai-chisei/issues/410)
Date: 2026-07-28
Status: **recommendation complete**

## Decision question

What is the smallest plane-owned contract that lets an authorized operator
resolve intentionally parked `runtime_dispatch` work and lets any authorized
host resume or replace the attempt without weakening fencing, provenance, or
idempotency?

## Recommendation

Keep the existing `ActionEffect` and `operation_id` as the stable work and
receipt identities. Change `parked` from immediately claimable to a durable
`awaiting_continuation` lifecycle state (retaining `parked` as the v1 wire
value during migration). Resolve it by submitting a governed
`resolve_parked_work` **Action transition**, subject to policy, approval,
authorization, idempotency, and audit before it can make the same effect ready
to resume.

A dedicated RPC may remain the typed wire command, but it is not an
administrative side channel. It submits and returns a durable resolution
Action. If policy permits immediate execution, admission records the Action,
appends the immutable continuation, and moves the effect to `pending` in one
transaction. If approval is required, the Action remains pending approval and
the effect remains parked until the approved Action is invoked.

The next claim returns that immutable continuation record. Its claim generation
is still the disposable runner attempt and remains the fence for heartbeat,
claim-event reporting, and terminal acknowledgement.

This is **plane-owned parked resolution through a governed Action transition**
(option 1 with the Action-transition shape), using append-only park,
resolution-Action, and continuation records rather than mutable answer fields
on `ActionEffect`. It deliberately does not create a successor effect.

```text
stable operation_id
  └─ stable effect_id
       ├─ claim generation 1 ── park generation 1
       │                         └─ awaiting continuation
       │                              └─ governed resolution Action
       │                                   └─ immutable continuation 1
       ├─ claim generation 2 ── resume or replacement
       └─ ...
```

## Evidence and constraints

### Current contract

- `ActionInstance.operation_id` is the existing harvest and receipt spine.
- Runtime hosts claim an `ActionEffect`, not the parent instance.
- A claim already has a monotonically increasing generation, an opaque fencing
  token, a runtime owner, and an expiry.
- `AckActionWork(parked)` currently clears the live lease and makes the effect
  immediately claimable.
- A subsequent claim clears `failure_reason`, so that field cannot carry
  durable continuation input.
- Claim, heartbeat, and acknowledgement require namespace write access.
- Completed and failed acknowledgements backfill the operation receipt; parked
  acknowledgement currently does not record a durable intervention.

The project ontology validates these boundaries with provenance from Shikigami:
`SekaiChiseiGovernancePlane` is the external system of record;
`PlaneClaimLease` is identified by runtime id, generation, fencing token, and
expiry; and `ClaimedPlaneWork` maps the plane `operation_id` to the host logical
operation id. The research adds the proposed parked record, governed resolution
Action, and continuation concepts with provenance to this document.

### Prior art

ClawSweeper separates durable job identity, disposable GitHub Actions attempts,
and resumable logical sessions. A replacement runner registers the same work
key, attempts `thread/resume`, and starts a new thread if that checkpoint is
unavailable while preserving the durable job identity. Maintainer intervention
is durable coordinator state, mutations are idempotent and exact-revision
checked, and automatic repairs have per-head and per-job attempt caps.

The transferable rules are:

1. durable work identity must survive runner replacement;
2. a checkpoint is a recovery aid, not the work identity or authority;
3. operator input must be durable coordinator state;
4. retries and mutation authority must be bounded and fenced; and
5. failure to resume should rebuild under the same logical work identity.

The plane should adopt these identity and safety rules without importing
GitHub-, Codex-, or runtime-specific concepts into the core protocol.

Prior-art sources:

- [Steerable Repair Automation](https://clawsweeper.bot/steerable-repair-automation.html)
- [Auto-Updating ClawSweeper PRs](https://clawsweeper.bot/repair/auto-update-prs.html)

## Identity and fencing invariants

| Identity | Lifetime | Owner | Invariant |
| --- | --- | --- | --- |
| `operation_id` | Whole governed operation | Plane | Never changes across park, resume, or replacement; remains the receipt spine. |
| `effect_id` | Whole dispatch work item | Plane | Never changes across park, resolution, resume, or replacement. |
| `claim_generation` | One host claim attempt | Plane | Increases on every successful claim; fences all claimant mutations. |
| `park_generation` | One intentional wait cycle | Plane | Increases on every accepted parked acknowledgement; fences operator resolution. |
| `resolution_action_id` | One submitted governed resolution | Plane | Durable across approval and invocation; exactly one invoked Action may resolve `(effect_id, park_generation)`. |
| `resolution_id` | One invoked continuation | Plane | Immutable, bound to the resolution Action, and unique for `(effect_id, park_generation)`. |
| `request_id` | One caller mutation | Caller, recorded by plane | Same key and same canonical digest replay; same key with different digest fails. |
| `checkpoint_ref` | Optional logical recovery handle | Claiming host supplies in its fenced park ack; plane stores | Structured store id plus opaque object id, resolved only through an allowlisted authorized provider; never a raw URL/path or authority. |

`claim_generation` and `park_generation` solve different races. A claim
generation prevents an old runner from mutating the current attempt. A park
generation prevents an answer intended for an older wait from resolving a
newer wait after the work was resumed and parked again.

## Proposed protocol

### Durable records

Add these fields to `ActionEffect`:

```proto
uint64 park_generation = 16;
string active_resolution_id = 17;
uint32 claim_attempt_count = 18;
uint32 lease_expiry_count = 19;
uint32 park_count = 20;
string lifecycle_state = 21;
string retry_policy_version = 22;
string retry_policy_digest = 23;
uint32 max_claim_attempts = 24;
uint32 max_lease_expiries = 25;
uint32 max_park_cycles = 26;
```

`lifecycle_state` names the semantic state (`ready`, `claimed`,
`awaiting_continuation`, `completed`, `failed`, `dead_lettered`, or
`superseded`). During compatibility migration, the existing `status` remains
the public v1 projection: `awaiting_continuation` projects as `parked` and
`ready` projects as `pending`. New logic evaluates the lifecycle state, not the
legacy status string.

The retry-policy version, digest, and limits are immutable admission snapshots.
Later Action type or namespace-policy changes do not retroactively change an
existing effect’s retry budget. A new superseding effect may use the newer
policy.

Add an immutable park record created by the fenced claimant:

```proto
message ActionWorkPark {
  string park_id = 1;
  string effect_id = 2;
  string namespace = 3;
  string operation_id = 4;
  uint64 park_generation = 5;
  uint64 claim_generation = 6;
  string checkpoint_ref = 7;
  string checkpoint_digest = 8;
  string reason = 9;
  string parked_by = 10;
  int64 parked_at_ms = 11;
  string request_id = 12;
  string request_digest = 13;
  string checkpoint_store_id = 14;
}
```

Extend the existing parked acknowledgement with optional bounded
`checkpoint_store_id`, `checkpoint_ref`, and `checkpoint_digest` fields plus a
required `request_id`. The reference is an opaque id within the named store,
not a URI, filesystem path, provider credential, or executable locator. The
plane admits only configured store ids allowed by namespace and runtime policy.
The three checkpoint fields are an all-or-none tuple: all must be absent, or
the store id and reference must be non-empty and the digest must use a supported
format (`sha256:<64 lowercase hex>` in v1). Partial or unsupported tuples fail
before any state mutation.

Consumers resolve it only through the configured checkpoint-provider adapter
for that store. The adapter rechecks namespace and runtime authority, applies
network/filesystem egress policy, returns bounded bytes, and verifies the
recorded digest before deserialization. Hosts never pass the opaque id to a
generic HTTP client, shell, or filesystem API.

Only the live fenced claimant can create this record. The canonical digest
binds effect id, runtime id, claim generation, fencing token identity,
checkpoint store and metadata, reason, and requested outcome.

The server derives `parked_by` from authenticated context. It first loads the
effect-derived namespace, authenticates the same runtime identity recorded by
the original request, rechecks current namespace authority, and then checks
durable park-ack idempotency. The same key and digest returns the original park
record even after the lease was cleared; the same key with a different digest
fails. Replay bypasses only the now-impossible live-fence guard, never
authentication, runtime-identity matching, current authorization, or response
disclosure policy.

Only when no replay exists does the server validate the live fence, increment
`park_generation`, and store the park record in the same transaction that
changes the effect to `parked`. A resolver references the record; it cannot
reassert or replace host-produced checkpoint metadata.

Add an immutable, access-controlled resolution input at governed Action
submission:

```proto
message ParkedWorkResolutionInput {
  string resolution_input_id = 1;
  string effect_id = 2;
  uint64 park_generation = 3;
  string input_json = 4;
  string input_digest = 5;
  string reason = 6;
  string submitted_by = 7;
  int64 submitted_at_ms = 8;
}
```

The validated canonical payload is retained so an approval-delayed invocation
does not depend on the submitting process or attempt to reconstruct content
from a digest. Reads require live namespace authorization and apply
classification, retention, and redaction rules. Audit, approval summaries, and
logs contain only the record id, digest, and bounded non-sensitive metadata.

Add an immutable continuation child created at invocation:

```proto
message ActionWorkContinuation {
  string resolution_id = 1;
  string effect_id = 2;
  string namespace = 3;
  string operation_id = 4;
  uint64 park_generation = 5;
  string input_json = 6;
  string input_digest = 7;
  string park_id = 8;
  string resolution_action_id = 9;
  string resolution_input_id = 10;
  string reason = 11;
  string decided_by = 12;
  int64 decided_at_ms = 13;
  string request_id = 14;
}
```

`input_json` is bounded structured continuation input, not free-form execution
authority. The server stores its canonical digest and applies the same
classification, retention, audit, and disclosure rules as other potentially
sensitive governed input. `decided_by` comes only from authenticated context;
the request cannot assert it.

### Governed resolution Action

Define a built-in, versioned `resolve_parked_work/v1` Action transition. Its
input schema is:

```proto
message SubmitParkedWorkResolutionActionRequest {
  string effect_id = 1;
  uint64 expected_park_generation = 2;
  string input_json = 3;
  string reason = 4;
  string request_id = 5;
}

message ParkedWorkResolutionAction {
  string resolution_action_id = 1;
  string effect_id = 2;
  string namespace = 3;
  uint64 expected_park_generation = 4;
  // denied | pending_approval | rejected | invoked | cancelled | stale
  string status = 5;
  string policy_version = 6;
  string approval_id = 7;
  string decided_by = 8;
  int64 created_at_ms = 9;
  int64 invoked_at_ms = 10;
  string resolution_input_id = 11;
}

message SubmitParkedWorkResolutionActionResponse {
  ParkedWorkResolutionAction action = 1;
  ActionEffect effect = 2;
  ActionWorkContinuation continuation = 3;
  ActionWorkPark park = 4;
  bool replay = 5;
}
```

The command reuses the project’s governed-Action policy and approval ownership
rather than inventing permission rules inside the claim store. The built-in
transition is namespace-scoped and may be invoked only by the authenticated
principal captured on the Action or by the existing approval-resumption path.
An approval decision authorizes invocation; it does not itself mutate the
effect.

Submission has two transactional branches after common validation:

1. authenticates the principal and checks namespace write authority;
2. loads the effect-derived namespace, validates the bounded request, and
   canonically hashes the request including `expected_park_generation`;
3. checks the durable idempotency record before requiring the current effect
   state: an identical key and digest returns the original resolution Action
   with `replay = true`, while a digest mismatch fails;
4. locks the effect and verifies `status == parked`;
5. compares `expected_park_generation` and loads its immutable park record;
6. stores the immutable resolution input and resolves policy;
7. if policy denies, records a durable `denied` Action plus policy,
   idempotency, and audit evidence, creates no continuation, leaves the effect
   awaiting continuation, and commits that fail-closed result atomically;
8. if approval is required, records `pending_approval` and commits input,
   Action, policy evidence, approval linkage, idempotency, and audit atomically
   without changing parked state; or
9. if policy permits immediate execution, performs every invocation guard and
   commits input, an `invoked` Action, continuation, ready effect, receipt,
   idempotency, and audit in this same transaction.

Delayed invocation after approval:

1. locks the resolution Action, effect, and park record;
2. verifies the Action is invokable, the effect is still parked, and its park
   generation still matches;
3. verifies no other resolution Action was invoked for the tuple;
4. loads the Action-bound immutable resolution input and inserts the immutable
   continuation and intervention evidence;
5. marks the resolution Action `invoked`;
6. sets `active_resolution_id`, changes lifecycle state to `ready`, and projects
   legacy status as `pending`; and
7. commits Action, continuation, effect, receipt, and audit changes atomically.

There is no committed intermediate “immediately invokable” state. Immediate
execution either commits the complete transition or rolls back the entire
submission. Only approval-required Actions wait between transactions, and
their durable `pending_approval` state plus immutable input supports later
invocation.

`ClaimActionWorkResponse` gains the referenced continuation. Once claimed, the
continuation and park snapshots are immutable input for that claim generation.
A later park must increment `park_generation`, append its own park record, and
clear `active_resolution_id` in the same transaction; old park and continuation
rows remain retained provenance.

### Fenced claim events

Add a narrow `ReportActionClaimEvent` RPC rather than trusting an unfenced
generic receipt report for attempt-control facts:

```proto
message ReportActionClaimEventRequest {
  string effect_id = 1;
  string runtime_id = 2;
  uint64 claim_generation = 3;
  string fencing_token = 4;
  // resume_started | resume_succeeded | checkpoint_unavailable |
  // replacement_started
  string kind = 5;
  string checkpoint_digest = 6;
  string reason_code = 7;
  string request_id = 8;
}
```

The RPC validates the live, unexpired claim fence and idempotency tuple, then
appends the corresponding `attempt_started` or `human_intervened` event to the
bound operation receipt with the effect id, claim generation, park generation,
and resolution id. It carries bounded reason codes, never checkpoint content.

A claimant that cannot restore a checkpoint reports
`checkpoint_unavailable`, then `replacement_started`, and rebuilds context
under the same `operation_id`, `effect_id`, and live claim generation. It does
not need a new resolution or successor effect.

## State machine

| From | Command / event | Guard | To | Durable result |
| --- | --- | --- | --- | --- |
| `pending` | claim | authorized; retry budget open | `claimed` | Increment claim generation/count; create lease fence. |
| `claimed` | heartbeat | live matching fence | `claimed` | Extend lease. |
| `claimed` | lease expiry | clock/reconcile observes expiry | claimable | Clear live authority; increment expiry count; same effect may be reclaimed if budget remains. |
| `claimed` | ack completed | live matching fence | `completed` | Terminal effect and receipt outcome. |
| `claimed` | ack failed | live matching fence | `failed` | Terminal effect and receipt outcome. |
| `claimed` | fenced park ack | live matching fence, or exact durable replay | `awaiting_continuation` (`parked` v1) | Increment park generation/count once; append immutable host checkpoint metadata; clear lease and active resolution; append intervention evidence. |
| `awaiting_continuation` | submit resolution Action | namespace write; matching park generation; retry budget open | `awaiting_continuation` | Persist governed Action; invoke immediately or wait for approval. |
| `awaiting_continuation` | invoke approved resolution Action | Action invokable; matching park generation | `ready` (`pending` v1) | Append immutable continuation and audit; make same effect claimable. |
| `ready` after resolution | claim | authorized | `claimed` | Return active continuation and resolution Action provenance as immutable claim input. |
| `claimed` | checkpoint unavailable | live matching fence | `claimed` | Append fenced claim event; replacement may start under same claim. |
| non-terminal | retry/park cap reached | transactional policy check | `dead_lettered` | Terminal operational failure with reason and receipt outcome. |
| non-terminal | explicit cancellation/replacement | authorized expected revision | `superseded` | Terminal record; never claimable. |

`awaiting_continuation` / legacy `parked` is not claimable. `ready` / legacy
`pending` is claimable. Lease-expired `claimed` work is reclaimable without
operator input because expiry is infrastructure recovery, not an intentional
human wait.

## Retry, poison, superseded, and dead-letter semantics

The plane owns:

- total successful claim count;
- lease-expiry count;
- park/resolution count;
- maximum values captured from governed Action type/admission policy;
- whether another claim or resolution may proceed; and
- terminal `dead_lettered` / `superseded` transitions and audit evidence.

The host owns:

- bounded internal retries while its lease remains live;
- checkpoint creation and restoration;
- the decision to report checkpoint unavailability and rebuild; and
- choosing `failed` versus `parked` for an outcome, subject to plane limits.

Recommended v1 defaults are conservative and configurable at admission:

- no automatic cap on normal completed work beyond the existing policy;
- a finite `max_claim_attempts`;
- a finite `max_lease_expiries`;
- a finite `max_park_cycles`; and
- no hidden host-local retry budget that can indefinitely defer a terminal ack.

The implementation issue must choose concrete defaults with operator
configuration evidence. The resolved limits and policy digest are frozen on
the effect at admission. Reaching a cap atomically moves the effect to
`dead_lettered`; it never silently leaves poison work claimable. A superseding
action does not delete the old effect or reuse its id.

## Race analysis

| Race | Required outcome |
| --- | --- |
| Stale answer for park generation N after work parked again at N+1 | Resolution compare-and-swap fails; no continuation or audit mutation is committed. |
| Duplicate identical Action submission after effect became ready or claimed | Idempotency lookup precedes the parked-state CAS; same request id and digest returns the original resolution Action with `replay = true`. |
| Park ack committed but response lost | Park-ack idempotency lookup precedes the live-fence guard; identical key and digest return the immutable original park record after the lease was cleared. |
| Park ack key reused with different checkpoint metadata or outcome | Digest conflict fails without disclosing or replacing the original park record. |
| Same request id, different answer | Fail idempotency conflict; preserve the first record. |
| Two concurrent resolution Actions | Both may be submitted only if policy permits, but transactional invocation admits exactly one continuation for the park generation; the loser becomes cancelled/superseded without mutating the effect. |
| Approval arrives after a newer park generation | Invocation compare-and-swap fails and records the Action as stale; approval never bypasses the live lifecycle guard. |
| Resolution Action is rejected or cancelled | Effect remains awaiting continuation and unclaimable; a new authorized Action may target the same park generation. |
| Policy denies resolution | Persist `denied` Action and decision evidence, create no continuation, and leave the effect awaiting continuation and unclaimable. |
| Submitting process exits while approval is pending | Invocation loads the immutable resolution input persisted with the Action; no host-local request state is required. |
| Crash during policy-allowed immediate resolution | Input, Action, continuation, effect, receipt, idempotency, and audit all commit or all roll back; replay returns the committed result or retries from parked state. |
| Concurrent claim while parked | Claim fails because `parked` is not claimable. |
| Claim racing successful Action invocation | Claim can succeed only after the invocation transaction exposes `ready` / `pending` plus its continuation atomically. |
| Lease expires while host reports resume result | Fenced event fails; expired claimant cannot establish attempt facts. |
| Old claimant acks after resolution or reclaim | Claim generation/token mismatch fails. |
| Resolution arrives after cancellation or supersession | Status compare fails; terminal state wins. |
| Checkpoint unavailable | Live claimant records a fenced event and starts replacement under the same identities. |
| Database or audit write fails | Resolution/claim transition rolls back; no split continuation, effect, receipt, or audit state. |

## Threat analysis

| Threat | Control |
| --- | --- |
| Forged operator answer | Authenticate; derive actor server-side; submit through the built-in governed Action; enforce namespace policy, approval, and audit before invocation. |
| Cross-namespace resolution | Load namespace from effect, not request metadata; authorize that namespace before content disclosure or mutation. |
| Replay against a later park | Require exact `park_generation`; bind it into the canonical request digest. |
| Ambiguous park acknowledgement | Require key-and-digest idempotency before the live-fence guard, but still authenticate the original runtime and recheck current effect-derived namespace authority before disclosure; never accept a different request under an expired fence. |
| Checkpoint substitution | Accept the logical store handle and digest only from the live fenced claimant; bind them into the immutable park record and verify both authorization and digest through the configured provider before resume. |
| Checkpoint confused deputy / SSRF / local-file access | Reject URLs, paths, credentials, and unknown store ids at park time. Consumers never dereference the opaque id with generic network, shell, or filesystem APIs. |
| Malicious continuation text | Treat as untrusted data; schema/size validate; do not interpret it as plane policy or tool authority. |
| Sensitive answer disclosure | Apply classification, ACL, retention, and redacted list behavior; do not place raw input in audit evidence or logs. |
| Approval confused with execution | Approval only makes the resolution Action invokable; the transactional invocation rechecks effect state, park generation, policy invariants, and idempotency. |
| Stale host mutation | Require live `(runtime_id, claim_generation, fencing_token)` on heartbeat, claim events, and ack. |
| Retry exhaustion bypass | Check counters and terminal transition in the same transaction as claim or resolution. |
| Split SQLite/PostgreSQL behavior | Require shared backend conformance before the RPC is advertised. |

## Options compared

| Option | Verdict | Decisive trade-off |
| --- | --- | --- |
| 1. Plane-owned parked resolution | **Choose as a governed Action transition** | Preserves plane SoR and stable identities while reusing policy, approval, authorization, and audit. Immutable Action/continuation children avoid mutable-answer history loss. |
| 2. Successor effect | Reject for v1 | Adds effect identity churn and ordering/cancellation complexity without improving fencing; weakens `effect_id` as durable job identity. |
| 3. Host-local recovery | Reject | Creates host affinity, loses authenticated provenance, and cannot safely recover after host loss. |
| 4. Terminal park plus separately admitted continuation | Reject | Duplicates admission work and makes `parked` terminal in conflict with the claim API vocabulary; a successor may be admitted later only for genuinely new work. |

A bare resolution RPC that directly flips effect state is also rejected. The
typed RPC is acceptable only as the submission surface for the governed Action
and its invocation lifecycle.

## Compatibility and migration

This is an additive pre-1.0 protocol change with one intentional semantic
correction: existing clients must no longer expect a parked effect to be
immediately reclaimable.

Migration obligations:

1. Add immutable park, resolution-input, resolution-Action, continuation,
   approval-linkage, and park/Action/event idempotency tables for SQLite and
   PostgreSQL.
2. Add effect lifecycle state, counters, park generation, and immutable
   admission retry-policy snapshot with zero/default compatibility.
3. Existing rows in `parked` state have no authenticated continuation. Keep
   them parked, project them as `awaiting_continuation`, and require an explicit
   governed resolution Action; never synthesize an answer.
4. Existing `pending`, `claimed`, `completed`, and `failed` rows retain their
   meaning.
5. Generated proto copies, RPC inventory, capability metadata, docs, and both
   backend conformance fixtures must change together.
6. Resolution Action submission must couple policy/approval evidence,
   idempotency, and audit. Policy-allowed immediate submission/invocation must
   additionally couple Action, effect, continuation, receipt, and audit in that
   same transaction; delayed invocation after approval must couple those same
   records transactionally. If the current cross-record path cannot do that,
   the implementation must establish a backend transaction boundary before
   exposing the command.
7. Rollback requires a database backup once new continuations exist; an older
   binary would otherwise misinterpret parked rows as immediately claimable.

Single-site remains the supported v1 claim model. A future multi-site profile
must provide one serialization owner for each `effect_id`; park generation is a
logical fence but does not by itself make cross-site writes linearizable.

## Impact assessment

| Surface | Evidence found | Required change/check | Risk if missed |
| --- | --- | --- | --- |
| Product boundary | Plane owns claim state; hosts execute | Keep checkpoint bytes and runtime tools out of plane | Plane becomes a runtime or split SoR |
| Public API | Additive claim and governed-Action messages; changed parked semantics | Proto compatibility review and generated-client tests | Old clients hot-loop or silently restart work |
| Governance | Existing Action policy and approval owners already constrain changes | Built-in transition must reuse policy/approval and recheck at invocation | Administrative side channel bypasses governance |
| Authorization | Current claim mutations require namespace write | Server-derived actor, effect-derived namespace, Action submission/invocation and disclosure tests | Forged or cross-namespace answers |
| Persistence | SQLite/PostgreSQL both implement claims | Shared transactional park/input/Action/continuation schema and conformance, fresh + upgraded DB tests | Split state or backend drift |
| Audit/receipt | Terminal ack backfills receipts; park does not | Durable park, Action submission/approval/invocation, resume/fallback evidence | Unreconstructible operator decision |
| Idempotency | Claim request id covers only live same-owner claim | Durable Action-submission, invocation, and claim-event key+digest records | Replay or conflicting answers |
| Retry safety | Current parked work is immediately claimable | Counters, policy caps, dead-letter/supersede states | Poison loops and unbounded cost |
| Secrets/privacy | Continuation may contain operator content | Bounded schema, classification, ACL, retention, redacted audit | Sensitive input leaks |
| Operations | Single-site claim semantics documented | Metrics for parked age, expiry count, retry caps, dead letters | Invisible stuck or poison work |
| Consumer | Shikigami maps claimed work to `RunRequest` | Preserve logical operation id; validate checkpoint digest and fallback | Host affinity or duplicate logical work |

## Acceptance evidence for implementation

The implementation should include deterministic shared SQLite/PostgreSQL tests
for:

- park → resolve → claim → resume → completed;
- park → submit resolution Action → approve → invoke → claim;
- policy-allowed immediate resolution Action invocation;
- policy denial persists a denied Action and leaves work awaiting continuation;
- injected failure proves immediate input/Action/continuation/effect/receipt/
  audit atomicity and deterministic replay;
- rejected/cancelled resolution Action leaves work awaiting continuation;
- delayed approval consumes the durable immutable resolution input after the
  submitting process is gone;
- park → resolve → claim → checkpoint unavailable → replacement → completed;
- fenced park metadata, checkpoint integrity, and resolver inability to replace
  the checkpoint reference;
- unknown checkpoint store, raw URL/path rejection, cross-namespace store
  denial, and digest mismatch without unsafe dereference;
- partial checkpoint tuple and unsupported digest rejection;
- lost-response park-ack replay and conflicting park-ack digest;
- replay denial for a different runtime identity or principal that lost current
  namespace authority;
- stale park generation, duplicate resolution, and idempotency conflict;
- concurrent resolution Actions, stale approval, invocation, and claim;
- lease expiry, reclaim, and late fenced event/ack;
- cross-namespace denial and unauthorized continuation reads;
- policy denial, approval identity, and invocation-time revalidation;
- retry-cap dead-lettering and explicit supersession;
- admission retry-policy immutability after Action type or namespace-policy
  changes;
- fresh schema and upgrade of pre-continuation parked rows; and
- receipt/audit coupling under injected transaction failure.

## Smallest safe implementation split

One implementation issue and one PR can own the coherent plane contract:

1. proto and immutable park/resolution-input/resolution-Action/continuation
   domain records;
2. SQLite and PostgreSQL migrations plus transactional storage;
3. governed Action submission/approval/invocation and fenced claim-event RPCs;
4. changed claimability and retry/dead-letter rules;
5. receipt/audit coupling, conformance tests, and operator docs.

The Shikigami consumer should be a separate issue in that repository, blocked
on the plane implementation. It should map continuation input, verify optional
checkpoint digests, attempt resume, report fallback, and retain the same
logical operation id.

## Exit decision

Implement plane-owned resolution of the **same effect** as a governed,
versioned **Action transition**, fenced by a new monotonic **park generation**,
with append-only park, resolution-Action, and continuation records plus fenced
claim events. A park is an intentional wait, not an immediate retry. Approval
may authorize the transition but invocation must recheck and atomically apply
it. Checkpoint loss starts a replacement attempt under the same operation and
effect identities. The plane owns policy, approval, retry admission, and
terminal poison state; hosts own bounded execution retries and checkpoint
mechanics.
