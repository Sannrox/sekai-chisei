# ADR 0073: Typed objects are source-backed and Action-written

- Status: accepted
- Date: 2026-09-14
- Owners: @Sannrox
- Discussion: https://github.com/Sannrox/sekai-chisei/discussions/907
- Issue: https://github.com/Sannrox/sekai-chisei/issues/876 (#876)
- Supersedes: none
- Superseded by: none
- Related: [ADR 0020](0020-shared-type-revisions-and-object-sync.md),
  [ADR 0060](0060-additive-source-type-descriptors.md),
  [ADR 0066](0066-object-set-evaluate.md),
  [ADR 0036](0036-open-table-projections.md)

## Context

Objects and links are stored as graph rows today. Those rows are written by
inbound source batches, versioned Actions, and generic object/link RPCs. Issue
#876 asked whether a type should instead be backed by registered sources and
Action edits, with a derived index for query. [ADR 0066](0066-object-set-evaluate.md)
already forbids treating a descriptor, page, cached set, or search index as a
second object authority. It does not forbid a rebuildable derived index.

## Decision

1. A typed object is a fact of a type revision. It is produced by a
   **registered source mapping** (inbound object sync and additive source-type
   descriptors) or by a **versioned Action** (`object_kind` /
   `object_mutation`). Graph rows are the current persistence of those facts.
   They are not themselves the product.
2. A derived index, cache, page, or materialization is a **rebuildable
   projection**. It is never recovery material and never a second object
   identity. Deleting the index must remain recoverable from sources, Action
   receipts, and graph persistence.
3. Derived views and function results are not persisted onto a type revision
   ([ADR 0020](0020-shared-type-revisions-and-object-sync.md)). Transforms may
   write datasets or snapshots; they must not mint object identity.
4. Generic `CreateObject`, `UpdateObject`, `DeleteObject`, and `CreateLink`
   remain the current escape hatch. They are not the destination write model.
   Closing them is a later change set, not this ADR.
5. This ADR does not pick an indexer, per-type table layout, or query engine.
   #877, #878, and #889 stay implementation-blocked until the published
   envelope is measured.

## Alternatives considered

- Treat graph rows as the meaning of objects. Rejected: that confuses
  persistence with identity. Sources and Actions already define how a type
  revision receives facts.
- Treat a search index or materialized set as object authority. Rejected:
  [ADR 0066](0066-object-set-evaluate.md).
- Adopt an external index engine now. Rejected: no 10⁷-object envelope exists
  in tree.

## Consequences

The product write paths are sync and `SubmitActionInstance`. Source-owned
objects already reject generic mutation. A later indexer, if measured, is a
projection rebuild. #870 remains a storage-engine question and is independent
of this meaning rule.

## Validation

Existing sync-batch, source-identity, and Action object-mutation tests remain
the write contract. A later #877 spike must publish the envelope on a declared
hardware profile and prove rebuild-from-receipts after deleting any derived
index.
