# Resolved evaluation manifests

`ResolveEvaluationPlan` freezes one situation-specific evaluation into an
immutable `chisei.resolved-evaluation-manifest/v1` document. It resolves exact
inputs only. It does not run evaluators, collect evidence, create waivers, make
a gate decision, or grant action authority.

The caller supplies:

- `chisei.evaluation-resolution-request/v1` and the exact
  `chisei.evaluation-resolver/v1` resolver version;
- namespace and idempotency request ID;
- an exact evaluation-plan version ID;
- opaque subject profile and identity plus the subject content digest;
- exact admitted-evidence object IDs; and
- a positive historical-or-current evaluation time. Future evaluation times
  are rejected against the server's resolution time.

The caller must have namespace write access. Authorization is checked before
plan lookup. The plan and every governed-invariant reference closure must also
be visible to the caller; the resolver never returns a partially disclosed
manifest.

## What resolution freezes

A resolved manifest binds:

- the plan version and canonical plan digest;
- subject profile, identity, and content digest;
- the content-addressed governed invariant-set ID and digest, including the
  profile digest used to resolve it;
- every applicable requirement version, content digest, and
  provenance-evidence reference;
- every selected evaluator-definition and implementation digest;
- exact node dependencies, typed inputs, canonical parameters, invariant
  contracts, and required/advisory classification;
- every valid waiver, its exact target invariant-version IDs, and its
  provenance-evidence references;
- every admitted evidence record's object ID, submission ID, content digest,
  type, schema/version, classification, observation/expiry times, and a digest
  of its source identity;
- evaluation time, authenticated resolving actor, and resolver version.

`invariant_set_digest` is the exact snapshot pin. There is no independent
"latest graph" or numeric graph-revision fallback.

The manifest digest covers all semantic fields above. `created_at_ms` is
storage provenance and is deliberately excluded, so identical immutable
inputs deduplicate to the first stored manifest. Manifest nodes, bindings,
evidence, waivers, and other set-like fields are canonically ordered before
hashing.

## Evidence and fail-closed outcomes

Resolution uses retained admitted evidence without returning its payload. Each
evidence object must:

- belong to the request namespace and remain visible;
- reference an available admitted submission;
- have been observed by the requested evaluation time and not be expired then;
- preserve the admitted content digest and classification;
- match the subject when explicitly supplied by the caller;
- match an invariant-required evidence type and a typed plan evidence binding;
  and
- have a classification admitted by the selected evaluator definition.

All explicitly requested evidence must be consumed by a matching node.
Provenance evidence referenced by facts and waivers is also validated and
frozen, but is not silently repurposed as evaluator input.

The response status is one of:

- `resolved`: a complete immutable manifest is returned and persisted;
- `unknown`: subject, invariant, waiver, visibility, coverage, or evidence
  inputs are insufficient or stale; or
- `unavailable`: an exact evaluator definition is missing, disabled, or
  superseded.

Blocked responses contain a bounded typed finding with severity `blocking`.
Codes are stable machine-readable categories such as
`invariant_uncovered`, `evidence_stale`, and `evaluator_unavailable`.
Identifiers are omitted from findings when including them could disclose a
hidden resource. The resolver does not choose a newer plan, evaluator, fact,
waiver, or evidence record as a fallback.

## Idempotency and historical replay

Successful resolution is keyed by `(namespace, authenticated actor,
request_id)`. Repeating the exact canonical request returns the originally
stored manifest, including its original creation time. Reusing that key with
different canonical content fails.

Historical replay is intentionally evaluated before current evaluator
availability. A manifest that resolved while an evaluator was enabled remains
replayable after that evaluator is disabled or superseded. A new request is
checked against current availability and fails closed. This preserves evidence
without making old evaluator availability authoritative for new work.

There is no independent public `Put`, `Get`, `List`, update, or delete lifecycle
for manifests. The resolution receipt is the lifecycle: the same authorized
request replays it, while downstream execution and gate APIs will reference its
digest.

## Backup, restore, retention, and rollback

SQLite backups must include `chisei_evaluation_manifests` and
`chisei_evaluation_manifest_requests` with evaluator definitions, plans,
governed facts, evidence submissions and projections, grants, audit, and
temporal history. PostgreSQL migration `0025_evaluation_manifests.sql` creates
the equivalent tables. Back up and restore them transactionally with the
referenced records.

Live resolution holds a write-excluding database snapshot until its immutable
request binding commits. PostgreSQL therefore requires at least two pooled
connections for this RPC: one holds the snapshot/table locks while existing
read APIs use another. The default pool size is 16.

Retain manifests and request bindings for at least as long as an execution,
gate decision, or operation receipt can reference their digest. Immutable
manifests are not rolled back or edited. Rollback selects a prior exact plan
for a new resolution request; it does not mutate historical evidence. Physical
deletion is not part of the v1 public API.

Existing evaluation-plan, `EvalSuite`, governed-subject, evidence-admission,
and operation-receipt APIs are unchanged.
