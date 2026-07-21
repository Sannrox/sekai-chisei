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

## Reconciliation and assurance

`evidence_due_at_ms` comes from the signed permit window. Reconciliation emits
an idempotent `missing_execution_evidence` governance alert after that deadline
unless terminal host evidence exists. Missing evidence remains unknown, never
success. Duplicate delivery is idempotent; contradictory or post-terminal
reports remain retained and raise a conflict alert.

Shomei can embed the canonical signed permit and admitted host report. Offline
verification proves integrity and binding, not unobserved host enforcement or a
physical effect. Host report, independent effect verification, and downstream
outcome retain separate receipt states and producer identities.
