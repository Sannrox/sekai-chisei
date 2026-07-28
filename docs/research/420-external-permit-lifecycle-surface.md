# External-action permit lifecycle surface

Issue: [#420](https://github.com/Sannrox/sekai-chisei/issues/420)

## Decision

Retain the ten external-action lifecycle RPCs. Do not add a consolidated
command RPC or compatibility shim.

The methods share the advanced-tier `chisei.approvals` persistence surface, but
that is not evidence that they share one security operation. Each method has a
different caller authority, side-effect class, transaction boundary, response
contract, or audit meaning. A typed command would move those distinctions into
an internal dispatch union without removing the underlying paths. During a
compatibility window it would increase the public surface from ten RPCs to
eleven.

This is a no-change result. It creates no refactor follow-up and requires no
Design Discussion because no public contract or trust boundary changes.

## Scope and sources

The inventory covers the consecutive external-action methods in
[`ChiseiService`](../../proto/chisei.proto), their implementations in
[`chisei_service.rs`](../../src/grpc/chisei_service.rs), SQLite permit storage
in [`external_permit.rs`](../../src/chisei/external_permit.rs), PostgreSQL
storage in
[`postgres_external_permit.rs`](../../src/db/postgres_external_permit.rs), and
the checked-in
[`chisei.rpc-inventory/v1`](../../tests/fixtures/chisei_rpc_inventory/v1.json).

Repository search found no maintained CLI, gateway, adapter, or example that
invokes these RPCs directly. In-repository calls are service tests; external
consumers use generated gRPC clients. This reduces migration evidence, not
migration risk: the protocol remains public.

All ten RPCs are classified `persistent`, `advanced`, and
`chisei.approvals` in the RPC inventory. That classification is deliberately
coarser than the trust boundaries below.

## Operation inventory

| RPC | Caller authority | Effect and durable boundary | Distinct evidence or result |
| --- | --- | --- | --- |
| `AuthorizeExternalAction` | Authenticated actor must equal the request actor and hold namespace/project write access | Claims an idempotency identity, evaluates action policy, reserves budget and blast radius, and stores an authorization decision | Authorization lifecycle decision audit keyed by authorization and lifecycle |
| `ResolveExternalActionApproval` | `root` or `local` control-plane administrator | Rechecks namespace access, policy revision, and expiry; compare-and-swaps a pending approval; releases reservations on denial | Approval lifecycle remains attributable to the administrator |
| `CancelExternalActionAuthorization` | Request actor, `root`, or `local` | Compare-and-swaps the authorization to cancelled and releases budget/blast-radius reservations | Cancellation remains distinct from approval denial |
| `IssueExternalActionPermit` | Authorization actor, `root`, or `local`, with namespace write access | Creates a signed online or policy-bounded offline permit; permit row and issuance audit commit together; idempotency is bound to authorization and mode | Returns the signed permit and records `issued` |
| `VerifyExternalActionPermit` | Any authenticated caller | Read-only trust, signature, host-binding, time, capability, and live-state validation; consumes no authority | Returns `valid` plus a reason and writes no lifecycle event |
| `RedeemExternalActionPermit` | Bound executor, `root`, or `local` | Rechecks signed host context and live authority, then atomically consumes an invocation and writes redemption audit; offline mode records later reconciliation with weaker guarantees | Returns a redemption identity and invocation ordinal |
| `RevokeExternalActionPermit` | `root` or `local` control-plane administrator | Idempotently stores a revocation handle, then records a dedicated revocation decision | Revocation is independent from authorization cancellation and kill switches |
| `SetExternalActionKillSwitch` | `root` or `local` control-plane administrator | Enables or disables an action, executor, harness, namespace, or signing-key emergency stop | Dedicated kill-switch audit records scope and state |
| `SetExternalPermitPolicy` | Control-plane administrator | Stores offline-eligibility and delegation bounds for a policy scope | Returns the stored policy; it is administration, not a permit transition |
| `DelegateExternalActionPermit` | Current permit subject with namespace write access | Verifies the parent and policy, transfers only narrower unused authority to one signed child, and records delegation with its parent chain | Returns a child permit; delegation remains distinct from ordinary issuance |

## Shared fields do not imply a shared command

`VerifyExternalActionPermit` and `RedeemExternalActionPermit` share the permit
and six host-context inputs. The shared fields represent the checks a host
must perform, not equivalent semantics:

- verify is a read-only diagnostic and returns a non-throwing validity result;
- redeem binds the authenticated executor, idempotency key, execution identity,
  invocation timing, region pin, and durable invocation count;
- online redeem checks cancellation, revocation, kill switches, and remaining
  invocations inside one SQLite transaction before inserting the redemption
  and audit row;
- offline reconciliation intentionally validates at the recorded invocation
  time and does not claim immediate revocation or global single use.

Combining these methods would make a read-only check and an authority-consuming
mutation share one permission and error surface. Hosts must continue to verify
before redeeming or executing, as required by
[`sekai.host-executor-permit-conformance/v1`](../host-executor-permit-conformance.md).

## Backend boundary

SQLite implements issue, delegation, live state validation, online redemption,
offline reconciliation, revocation, policy, and kill-switch state. PostgreSQL
implements authorization, issue, policy, revocation, and kill-switch storage,
but the community runtime fails closed for live permit-state validation,
online redeem, offline reconciliation, and delegated-permit persistence and
validation.

A single command RPC would therefore need operation-specific backend
capabilities or would return branch-dependent unavailable errors behind one
method. The current methods expose that fail-closed boundary directly and keep
the operator posture in
[`postgres-chisei-parity.md`](../postgres-chisei-parity.md) accurate.

## Consolidation estimates

The estimates count public RPC declarations, not message types or generated
client methods. Every option retains the existing authorization, validation,
persistence, and audit implementations behind a dispatcher.

| Option | Steady-state RPC count | Compatibility-window count | Implementation reduction | Security cost |
| --- | ---: | ---: | --- | --- |
| Combine approval resolution and cancellation | 9 | 11 | No lifecycle path removed; only dispatch moves | Mixes administrator approval with owner cancellation |
| Combine issue, revoke, and delegate | 8 | 11 | No signing, transfer, or revocation path removed | Mixes actor, administrator, and current-subject authority |
| Combine verify and redeem | 9 | 11 | Shared host-context construction only | Mixes read-only validation with transactional consumption |
| One lifecycle command for all ten | 1 | 11 | Replaces method dispatch with a large operation union | Hides least-privilege and backend guarantees behind branch tags |
| Retain the current surface | 10 | 10 | No churn | Trust boundaries remain explicit |

The compatibility count is eleven because a safe migration must add the new
command while retaining all ten old methods until generated clients migrate.
Removing old methods immediately would be a breaking protocol change and still
would not delete their internal behaviors.

## Failure analysis

Incorrect grouping creates concrete failure modes:

- a credential allowed to verify could accidentally gain redemption authority;
- a permit subject could reach administrator revocation or kill-switch
  operations through an overly broad command permission;
- cancellation could be treated as approval denial and lose the initiating
  actor or reservation-release semantics;
- delegation could be implemented as copying rather than transferring unused
  authority;
- offline reconciliation could inherit online claims about revocation or
  single-use guarantees;
- PostgreSQL could appear to support a command whose redeem or delegate branch
  must fail closed;
- generic command audit could collapse `issued`, `delegated`, `redeemed`,
  `reconciled`, `revoked`, and `cancelled` into an ambiguous mutation event.

Typed oneof payloads prevent invalid field combinations, but they do not
prevent these authorization, transaction, or audit errors.

## Revisit criteria

Reopen this decision only with evidence beyond RPC count, such as:

- measured client confusion that cannot be fixed in an SDK facade;
- repeated defects caused by duplicated validation outside the current shared
  permit helpers;
- a protocol-version transition already justified by another durable contract
  change; or
- a backend-neutral transaction that genuinely unifies two lifecycle effects
  without widening caller authority.

Prefer an SDK-level workflow helper when the goal is fewer client steps. Keep
the wire methods explicit unless a later design proves real implementation and
security simplification.
