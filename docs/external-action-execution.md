# External-action execution evidence

External-action authorization, permits, redemption, host execution, independent
verification, and downstream outcomes are separate facts. A permit authorizes a
bounded action. Redemption consumes that authority. Neither proves that the host
started, completed, or successfully affected a resource.

Hosts submit lifecycle observations through the normal Sekai evidence funnel
using evidence type `external_action_execution`, schema id and version
`external-action.execution-evidence/v1`, the authenticated evidence producer as
`host_identity`, a stable source identity with increasing sequence, and the
exact permit, redemption, and execution identifiers returned by Chisei.

```text
accepted -> started -> completed | failed | cancelled | outcome_unknown
```

A terminal report includes `finished_at_ms`; `started` includes
`started_at_ms`. Reports may contain enforced preconditions, normalized effects,
affected-resource references, bounded cost/resource counters, governed artifact
or compensation hashes, and exit/error classifications. Never include secret
values, private payloads, command output, or credentials.

The adapter SDK durable outbox and ordinary `SubmitEvidence` RPC remain the
transport. The producer and schema must be registered through the usual evidence
funnel. Admission and projection happen before external-action lifecycle
projection, so a rejected envelope cannot become execution evidence.

## Host conformance

Host integrations call `verify_for_executor` before redemption or execution.
It verifies the signature, trusted issuer/key, executor/harness, arguments,
targets, current preconditions, validity window, and required host capabilities.
An executor refuses the action when any requirement is unsupported. Shared tests
exercise both filesystem-style (`atomic_rename`) and HTTP-style
(`conditional_request`) executors.

## Offline leases

Offline permits are disabled until an administrator stores an
`ExternalPermitPolicy` for the authorization's exact policy scope. The policy
names eligible action types and caps both lease duration and invocation count.
Destructive actions are never eligible. The signed permit uses
`offline_bounded` mode and declares `offline_no_global_single_use` and
`offline_revocation_unavailable_until_expiry`; a disconnected host must enforce
the local count and later submit separately attributable execution evidence.

An offline lease does not provide global replay prevention or immediate
revocation. Duplicate observations remain visible during reconciliation, and
integrators must not describe the lease as exactly-once execution. Use online
atomic redemption for action classes that require either guarantee.

## Narrow delegation

Delegation is disabled unless the same stored policy explicitly names the
current permit subject as a delegator and sets a non-zero maximum depth. A
child can only reduce actors, exact targets, effects, validity, budget, volume,
blast radius, invocation count, and risk. The signed child preserves the
initiating actor and the ordered root-to-parent permit chain; issuance and
redemption reject missing, expired, revoked, malformed, or over-depth links.

Delegation transfers the remaining authority: a parent must be unused, can
have only one direct child, and cannot be redeemed after that child is stored.
This prevents sibling permits from multiplying the parent's envelope. Knowing
a permit or operation id never grants delegation authority. Offline leases are
not delegable because the control plane cannot observe local consumption or
retire every disconnected copy safely.

## Reconciliation and assurance

After reconnecting, an offline executor calls permit redemption as a
reconciliation operation for each locally consumed invocation before submitting
its execution evidence, including the local invocation timestamp. That timestamp
must fall inside the signed lease and cannot be later than reconciliation. The
control plane durably binds it with the permit, execution id, executor, and
invocation ordinal even when expiry or revocation was learned after execution.
Idempotency detects repeated reports and the signed invocation cap bounds
accepted reconciliation records; it cannot prove that a compromised or
permanently disconnected host reported every local invocation.

`evidence_due_at_ms` comes from the signed permit window. Reconciliation emits
an idempotent `missing_execution_evidence` governance alert after that deadline
unless terminal host evidence exists. Missing evidence remains unknown, never
success. Duplicate delivery is idempotent; contradictory or post-terminal
reports remain retained and raise a conflict alert.

Shomei can embed the canonical signed permit and admitted host report. Offline
verification proves integrity and binding, not unobserved host enforcement or a
physical effect. Host report, independent effect verification, and downstream
outcome retain separate receipt states and producer identities.
