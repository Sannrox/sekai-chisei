# ADR 0095: Ship evidence and findings as a types-only domain package

- Status: accepted
- Date: 2026-10-06
- Owners: @Sannrox
- Discussion: https://github.com/Sannrox/sekai-chisei/discussions/1281
- Issue: https://github.com/Sannrox/sekai-chisei/issues/1230 (#1230)
- Supersedes: none
- Superseded by: none
- Related: [ADR 0052](0052-capability-package-certification.md),
  [ADR 0073](0073-source-and-action-objects.md),
  [ADR 0079](0079-evaluation-promotion-gate.md),
  [ADR 0084](0084-system-one-action-function.md)

## Context

Issue #1230 asked for a reusable, versioned package that connects
observations, investigations, findings, external issue references, and
verification. Existing contracts already admit ontology classes, ObjectTypes,
governed Action types, evidence envelopes, and capability-package members.
A new findings store, workflow engine, or domain RPC would duplicate those
write paths and invent a second fact authority.

## Decision

1. The evidence and finding package is **types only**. It registers ontology
   classes, ObjectTypes, governed Action types, one evidence schema, and an
   evaluation member. It does not package live instances.
2. Members use the closed kinds from
   [ADR 0052](0052-capability-package-certification.md): `ontology`,
   `action_type`, and `evaluation`. Certification is not a runtime grant.
3. Typed objects are written by accepted evidence plus versioned Actions
   ([ADR 0073](0073-source-and-action-objects.md)). Observation required
   properties stay on the ObjectType and on the observation Action schema:
   source evidence, problem signature, occurrence identifiers, classification,
   and disposition.
4. Invalid, stale, conflicting, or unauthorized evidence is rejected by the
   existing evidence contract. The observation Action also requires
   `source_evidence` to name an unexpired accepted upsert submission in the
   same namespace targeting an observation. SubmitEvidence may quarantine that
   submission with `projection_target_missing` until the observation exists;
   that recoverable state still authorizes the observation Action. The write
   stamps the observation `external_id` from that evidence target, retries
   projection after the Action receipt is durable, and rejects a second
   object that would reuse the same namespace/external_id pair. That reuse
   check is plan-time, matching other object identity checks; a unique index
   on `(namespace, external_id)` is a store-wide schema change because empty
   `external_id` is common on other kinds. Rejected, expired, retracted, or
   unknown evidence does not create observation objects.
5. **Hypothesis** is a separate object kind from **investigation result** and
   **verification record**. The verification Action `subject_kind` enum admits
   only `feedback_investigation_result`, and the write loads that subject and
   requires its stored kind to be an investigation result with
   `measured=true`.
6. External tracker adapters are outside this package. No new domain-specific
   core RPC is added. SQLite is the reference store for package certification;
   ObjectTypes, Actions, and evidence already exist on both community
   backends.

## Alternatives considered

- A findings store and domain RPC. Rejected: a second fact authority next to
  evidence and `SubmitActionInstance`.
- Packaging live instances. Rejected: instances are namespace data, not
  reusable type identity.
- Treating hypotheses as investigation results so verification can name them.
  Rejected: a hypothesis is not a measured fact.

## Consequences

Operators apply the domain document, put the Action types, register the
evidence schema, and certify the package through existing admin surfaces.
Fixture documents live under `tests/fixtures/feedback/`. Downstream issue
delivery and tracker adapters remain later Issues.

## Validation

Crate tests install the fixtures into an in-memory runtime and cover portable
ontology import with provenance, package member certification, observation
lineage after accepted evidence, rejection of invalid/stale/conflicting/
unauthorized evidence without creating objects, missing required observation
properties, duplicate observation external identities, verification refusing a
hypothesis `subject_kind`, and verification refusing an unmeasured
investigation.
