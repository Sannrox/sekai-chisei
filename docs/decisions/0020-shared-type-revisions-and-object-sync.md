# ADR 0020: Keep shared type revisions, inbound object sync, and permit-backed external mutation separate

- Status: accepted
- Date: 2026-08-21
- Owners: @Sannrox
- Discussion: maintainer-accepted technology plan
- Supersedes: none
- Superseded by: none

## Context

Governed Action Instances already materialize `runtime_dispatch` and `notify`
effects. `external_mutate` was reserved and skipped. Evidence adapters admit
observations; they do not upsert objects with a stable source identity.
Workshop composition needs tenant-scoped type revisions that outlive one
authoring document.

## Decision

1. Object types, links, and actions live in a namespace-scoped **type
   revision** (`type_digest`). Instances are runtime facts of that revision.
2. Inbound **object sync** maps one system-of-record record onto one object
   identity. The first adapter family is `source_control.object_sync` for
   GitHub Issue and PullRequest records. Refresh, tombstone, and identity
   conflict are explicit. This is not a pipeline or transform product.
3. `external_mutate` materializes as `pending` when the admitted parameters
   include a `permit_id`. Without a permit the effect stays `skipped`.
   Completion, failure, and compensation stay on the existing permit path.
   There are no free-form webhook effects.
4. Dataset-backed lineage records source → dataset → object → action →
   write-back without inventing a second object identity.

## Alternatives considered

- Treat each authoring document as its own ontology. Rejected: the next use
  case would mint another world and sync would have nowhere shared to attach.
- Build a general pipeline or connector marketplace. Rejected: unbounded
  complexity before identity and write-back are proven.

## Consequences

- Composition products attach sync and write-back to type revisions.
- Evidence adapters remain observations; object sync is a distinct family.
- Plane-side mutation without a permit remains forbidden.

## Validation

- `sync_github_record` is deterministic for the same type digest and source id.
- `plan_effects_for_admit` emits `pending` `external_mutate` only with
  `permit_id`.
- Lineage bind fails closed when object or type identity is missing.
