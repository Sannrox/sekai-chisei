# ADR 0106: Namespace-scoped model review state and family enablement

- Status: accepted
- Date: 2026-10-13
- Owners: @Sannrox
- Discussion: none — resolved in https://github.com/Sannrox/sekai-chisei/issues/1493
- Issue: https://github.com/Sannrox/sekai-chisei/issues/1493 (#1493)
- Supersedes: none
- Superseded by: none
- Related: [ADR 0058](0058-model-platform-certification.md)

## Context

Route admission cannot default-deny models until review state exists, is
administrable, and is audited. Sekai Chisei has no deployment-environment
concept: policies are namespace-scoped and residency uses region labels.

## Decision

1. Scope is the namespace, two levels as for leak rules: the empty namespace
   is the instance default; a named namespace may override it. Lookup is
   namespace model, then namespace family, then instance-default model, then
   instance-default family. No separate environment label is stored.
2. Per-model identity is the resolved #1352 identity: provider, canonical
   model, and artifact digest when present (empty string when unpinned).
3. Family enablement is per namespace and per `ResidencyPolicy` region label.
   A model belongs to the family named by its provider. A per-model row
   overrides the family in the same namespace. Missing state is `disallowed`.
4. Set, revoke, and list require namespace-admin on a named namespace and
   credential admin (`root` / `local`) on the empty namespace.
5. Every mutation writes a decision-ledger row with actor and reason.
6. Operators run a one-shot `sekaictl admin model-review backfill`. It marks
   currently routed hosted runtimes as enabled families (origins still on
   `SEKAI_ROUTING_ENDPOINT_ALLOWLIST`; unset or empty admits none) and
   canonicalizes policy models through the provider registry. It inserts an
   enabled per-model or namespace-family row only when no covering inherited
   row exists, including an explicit `disallowed` decision and a
   region-scoped family. A hosted profile cannot override an inherited
   operator restriction. `RuntimeBackend::initialize` does not
   run it, so Sekai-only and Chisei-only schema planes stay intact. Route
   admission enforcement is deferred to #1494.

## Alternatives considered

- A new instance environment label. Rejected because each instance is already
  one deployment and it would fork the admin contract from namespace policy.
- Union of global and namespace rows like leak rules. Rejected because review
  state is an override, not a stacked allow-list.

## Consequences

- Fresh and upgraded stores gain `chisei_model_review` and
  `chisei_model_family_enablement` on SQLite and PostgreSQL.
- Experimental Chisei RPCs and `sekaictl admin model-review` are the operator
  surface. GATE:mig applies to the new tables and the backfill.

## Validation

- SQLite and PostgreSQL conformance cover set/revoke/list, family override,
  and audit evidence.
- Domain tests cover missing=disallowed, namespace override of global
  (including namespace family over a global model), and hosted/policy/
  availability backfill that does not override an operator family restriction.
