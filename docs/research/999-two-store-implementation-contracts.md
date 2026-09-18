# Two-store implementation contracts

Status: accepted with [ADR 0083](../decisions/0083-two-store-cutover-and-recovery.md)
Issue: [#999](https://github.com/Sannrox/sekai-chisei/issues/999)
Date: 2026-09-17
Scope: cutover, ownership, recovery, and validation plan. Not the runtime
split itself.

Source evidence: current `src/db/` schema families, `proto/sekai.proto`
`SubmitActionInstance`, [ADR 0065](../decisions/0065-workflow-action-postgres-parity.md),
[ADR 0069](../decisions/0069-operation-correlation.md),
[ADR 0080](../decisions/0080-dual-community-runtime-storage.md),
[ADR 0082](../decisions/0082-separate-chisei-and-sekai-durable-stores.md).

## Decisions recorded here

- Offline, restartable relocation. No production dual-write.
- Ownership follows the local atomic commit, not the table prefix.
- Existing reservation + `SubmitActionInstance` idempotency + reconcile.
- Public receipts correlate `operation_id`; each plane remains its own
  receipt authority.
- One-sided restore stays fenced until generations match.

Named deferred blockers: a hosted mikura ingest tag (#943) and object-index
authority cutover (#944) are orthogonal and do not block the first store-split
slice.

## Ownership matrix

Owner is the plane that can commit the authoritative transition in one local
transaction. Derived indexes stay with their source plane.

| Family | Owner | Writers | Authoritative vs derived | Local transaction group | Cross-owner reference | Retention / backup |
| --- | --- | --- | --- | --- | --- | --- |
| Objects, links, object types, datasets, object-type index, definition branches | Sekai | Sekai RPCs / Actions | Facts + rebuildable projections | Object mutation + audit | Chisei cites object/revision digests | Sekai backup |
| Authorization, tenants, grants, credentials, object security | Sekai | Sekai admin | Authoritative | Grant/activation + audit | Chisei never writes these | Sekai backup |
| Action types, instances, effects, work parks, workflow-action bindings/callbacks/commands | Sekai | `SubmitActionInstance` | Authoritative | ADR 0065 one transition | Chisei reservation cites `operation_id` | Sekai backup |
| Mutation audit, `RecordDecision`, evidence submissions, object changes | Sekai | Sekai | Authoritative audit | Same txn as the fact write | Public projection may show both receipts | Sekai backup |
| Coordination leases, handoffs, contention | Sekai | Sekai | Authoritative | Lease grant + audit | Chisei may request a lease via RPC | Sekai backup |
| Event streams, source sync, fact migration, federation snapshots | Sekai | Sekai | Authoritative + derived checkpoints | Per-stream local txn | None into Chisei | Sekai backup |
| Budgets, usage, transfers, topology | Chisei | Chisei | Authoritative | Reserve + usage event | Cites Sekai `operation_id` after commit | Chisei backup |
| Evaluation plans, manifests, executions, eval suites | Chisei | Chisei | Authoritative | Manifest + execution + Chisei receipt | May cite Sekai revision digests | Chisei backup |
| Chisei operation receipts, portfolio, kioku decision records, learning | Chisei | Chisei | Authoritative decision evidence | Decision + receipt | Correlates `operation_id` | Chisei backup |
| External-action permits, reservations, redemptions (Chisei tables) | Chisei | Chisei | Decision / permit | Permit issue + reservation | Sekai stores execution evidence only | Chisei backup |
| Gateway request aliases | Chisei | Gateway via Chisei | Derived translator state | Alias write | Not a third store | Chisei backup |
| `sekai_external_action_execution_evidence` | Sekai | Sekai | Commit/effect evidence | With action effect | Permit id is a protocol reference | Sekai backup |
| `sekai_action_approvals` | Chisei decision, Sekai admission copy | Chisei decides; Sekai records the admitted constraint | Split: decision vs enforcement | Do not join across stores | Approval digest on the admission request | Each plane's backup |
| `sekai_reservations` / `sekai_policy_decision_audit` | Sekai | Sekai | Object/coordination reservation and policy-compile audit | Local Sekai txn | Not Chisei budget reservations | Sekai backup |
| Portable ontology CLI DB | Neither | Ontology CLI | Out of scope | Own file | Not this split | Separate |

Unresolved rows: none that block the first typed-handle slice. Approval storage
is an explicit split (decision in Chisei, enforcement copy in Sekai) and must
not become a cross-database foreign key.

## Compatibility inventory

| Surface | Shipped name | Contract |
| --- | --- | --- |
| Action admission RPC | `SubmitActionInstance` | ADR 0082's `InvokeActionInstance` wording is a documentation error, not an API. |
| Caller operation identity | `request_id` / `x-sekai-operation-id` | One identity ([ADR 0069](../decisions/0069-operation-correlation.md)). Collision scope `(namespace, operation_id)` per plane. Not globally unique. Payload digest is a separate binding. |
| Public receipts | `OperationReceipt` projection | May include Chisei decision fields and Sekai commit fields. Each store remains authority for its own receipt body. |
| Combined config | `DB_PATH` / `DATABASE_URL` | Migration compatibility until relocation. Target: `SEKAI_DB_PATH` + `CHISEI_DB_PATH` (SQLite) or two URLs (PostgreSQL). |
| Gateway | translator | No third store. Uses the same typed hop as native gRPC. |
| Wrong-plane RPC | n/a | Reject. Authenticate the service hop. Recheck caller authorization at Sekai. |

## Transition / failure matrix

| Event | Who advances | Durable evidence | Outcome |
| --- | --- | --- | --- |
| Crash after Chisei reserve, before Sekai submit | Reconcile | Chisei reservation `pending` | Hold budget; retry submit or expire after policy |
| Crash after Sekai commit, before Chisei finalize | Reconcile | Sekai idempotent commit + missing Chisei finalize | Finalize; never treat as reject |
| Response lost after commit | Caller retry | Same `operation_id` | Idempotent replay; same receipts |
| Duplicate / conflicting admission | Sekai | Commit idempotency | Same commit or fail closed on digest mismatch |
| Stale revision / authorization | Sekai | Current grants + revision | Reject mutation; Chisei keeps incurred provider cost |
| Cancellation vs late commit | Reconcile | Timeout ≠ absent | Query Sekai by `operation_id` before release |
| Reservation expiry | Chisei | Expiry timestamp + Sekai absent | Release only after Sekai reports not committed |
| Service unavailable | Caller / reconcile | Pending reservation | Stay pending |
| Ambiguous external effect | Operator | Effect evidence unknown | Remain unknown; no exactly-once external claim |
| One-sided restore | Operator | Split generation mismatch | Mutating RPCs refuse until restamp |

## Migration and recovery

1. Deploy typed handles (still one physical DB is allowed only as an
   explicitly transitional facade behind those handles).
2. Add destination empty stores and refuse shared-path combined mode for new
   installs.
3. Quiesce writers. Copy Chisei families, then remaining Sekai families stay
   in place or are compacted. Restartable per family.
4. Validate counts, checksums, and generation stamps.
5. Raise the writer fence: old single-store writers fail closed.
6. Restore one store → startup compares generations → mutating RPCs stay
   refused until reconcile.

Rollback point: before the writer fence is raised, operators keep the
pre-copy files. After the fence, rollback is restore-both-from-the-pre-fence
snapshot, not a mixed pair.

## Validation plan

| Invariant | Evidence | State |
| --- | --- | --- |
| Typed Chisei handle cannot see Sekai SQL | Unit + compile boundary | proposed |
| Two physical stores in combined mode | Integration + config | implemented (#1005) |
| Same public API on combined and split | Public-API integration, gateway smoke | proposed |
| SQLite and PostgreSQL conformance per store | Shared conformance | proposed |
| Fresh install + upgraded retained data | Migration tests | implemented (#1006) |
| Crash after reserve / after commit | Fault-injection | implemented (#1007) |
| Duplicate admission | Integration | implemented (#1007) |
| One-sided restore fence | Restore test | proposed |
| Wrong-plane RPC rejection | Subprocess isolation | proposed |
| Unit-only proof of the split | — | insufficient |

## Implementation slices

Published from this preparatory Issue. Readiness is on each Issue.

1. [#1004](https://github.com/Sannrox/sekai-chisei/issues/1004) — typed `SekaiStore` / `ChiseiStore` handles; Chisei loses `RuntimeDb`. **Ready.**
2. [#1005](https://github.com/Sannrox/sekai-chisei/issues/1005) — combined mode opens two physical stores. Ready after #1004.
3. [#1006](https://github.com/Sannrox/sekai-chisei/issues/1006) — offline table relocation + writer fence. Blocked on #1005.
4. [#1007](https://github.com/Sannrox/sekai-chisei/issues/1007) — reserve / commit / finalize / reconcile across the typed hop. Blocked on #1006.
5. [#1008](https://github.com/Sannrox/sekai-chisei/issues/1008) — subprocess isolation and wrong-plane rejection. Blocked on #1007.
6. [#1009](https://github.com/Sannrox/sekai-chisei/issues/1009) — one-sided restore fence. Blocked on #1008.

Deferred orthogonal blockers: #943 (hosted ingest tag), #944 (object-index authority cutover). They do not block #1004.
