# ADR 0122: Catalog entries are governed objects, registered by stable source id

- Status: accepted
- Date: 2026-10-22
- Owners: @Sannrox
- Discussion: none — resolved in Issue #1559
- Issue: #1559
- Supersedes: none
- Superseded by: none
- Related: [ADR 0108](0108-permission-aware-search-index.md),
  [ADR 0076](0076-compiling-policy-entry.md),
  [ADR 0067](0067-definition-consumer-impact.md)

## Context

#1559 asks for one governed record per dataset, object type and pipeline:
who owns it, how it is tagged, what markings apply and where it comes from.
Datasets come from mizuchi, pipelines from kako, object types from the
published ontology. Search ([ADR 0108](0108-permission-aware-search-index.md))
already finds objects under the caller's compiled read policy, and the
catalog must not become a second metadata store with its own policy.

## Decision

1. **An entry is an object of kind `catalog_entry`** in the namespace it
   describes (`sekai.catalog-entry/v1`). Reads, counts, facets and search
   hits therefore follow the ordinary object read policy: namespace access,
   ACL, the marking lattice, row rules and purpose. The ADR 0108 index
   serves entries as object documents under the same rules, and an index
   rebuild gives the same results because the index is derived from the
   object store.
2. **Registration is idempotent by stable source id.** `RegisterCatalogEntry`
   derives the entry id from (namespace, entry kind, source system, source
   id). Registering identical content writes nothing; changed content goes
   through the audited object path, fenced on the stored snapshot and the
   namespace's object security generation, so the object change log is the
   history and concurrent writers cannot both win. It needs namespace write,
   the stored entry is checked like any object update (ACL, markings, object
   security policy, policy-driving properties), and a write freeze stops it.
3. **Only registration writes entries.** Generic object create, update and
   delete, and Action-written mutations, refuse the kind. Curation by owners
   (#1686) is a governed Action, not a generic write.

   Amended by #1686: an Action type may update a catalog entry, and only
   its `description`, `tags`, `owners` and `access_marking`, when the
   submitter is an owner or the steward. The marking only rises. Curated
   fields are listed in `curated`, and registration keeps their curated
   values.
4. **Markings only rise.** A registration keeps the least marking that
   dominates both the stored and the requested one, under the namespace's
   classification lattice when it has one; markings with no common bound
   fail closed. Lowering is the audited declassify path.
5. **Deregistration deprecates.** `deprecated: true` keeps the entry and its
   history with status `deprecated`; nothing is deleted.
6. **Object types follow the published ontology.** The plane keeps one
   entry per published object type (source system `sekai.ontology`) and
   deprecates entries for object types no longer published. An entry takes
   the object type's declared `access_marking`. Each entry carries the
   position of the published head in the namespace's publish chain (each
   publish names the head it replaced) as its source generation, a durable
   order no clock affects, so a sync for an older revision never overwrites
   a newer one's entry. A background reconciler on every Sekai instance
   (every 60 seconds) re-applies the current published head in every
   namespace, so entries follow a publish within one interval, and a sync
   missed by a crash, a failure or a race with a newer publish converges the
   same way. The publish itself never waits on or fails because of the
   catalog. A namespace under a write freeze is skipped, and so is
   every namespace while any tenant is frozen (the plane cannot attribute a
   namespace to a tenant there); both catch up after the freeze lifts.

## Consequences

- Entries appear by themselves after a publish, so object security
  activation does not require a policy for `catalog_entry` (it accepts one).
  In an activated namespace without that policy, entries are unreadable:
  reads fail closed rather than activation breaking.
- Owners and tags are stored as comma-separated properties, so a facet on
  them groups by the whole list. Per-value facets are later work.
- Lineage on entries (#1685): an entry binds to exactly one typed core
  artifact at registration (dataset, object type, transform, or source plus
  descriptor). Lineage is derived from those bindings and the transform
  graph; unbound entries have none. A target the caller cannot discover is a
  redacted placeholder. Owner curation (#1686) and service, release and
  environment entries (#1688) build on this record.

## Alternatives considered

- **A separate catalog table and search document kind.** A second store and
  a third index document type with their own policy wiring, for data the
  object store and ADR 0108 already govern.
- **Deriving entries on read only.** Not searchable, and gives mizuchi and
  kako no place to record ownership.
