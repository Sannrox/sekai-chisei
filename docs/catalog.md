# Data catalog

Catalog entries describe datasets, object types and pipelines: owners,
steward, tags, marking, schema summary, freshness and status. They are
experimental; `RegisterCatalogEntry` needs `SEKAI_EXPERIMENTAL_RPCS=1` or the
`experimental-rpcs` Cargo feature (see [rpc-maturity.md](rpc-maturity.md)).
The design is [ADR 0122](decisions/0122-governed-catalog-entries.md).

## Reading

An entry is an object of kind `catalog_entry` in the namespace it describes,
with properties `entry_kind` (`dataset`, `object_type` or `pipeline`),
`source_system`, `source_id`, `description`, `owners`, `steward`, `tags`,
`access_marking`, `schema_summary`, `freshness_ms` and `status` (`active` or
`deprecated`). Read and find entries with the ordinary object RPCs and
search (kind `catalog_entry`), under the same read policy as any object: a
caller without access to a namespace or marking sees no entry, count or
facet value for it.

## Registering

`RegisterCatalogEntry` records what a source system reports, keyed by its
stable id: one entry per namespace, entry kind, source system and source id.

- Needs namespace write; the stored entry is checked like any object update
  (ACL, markings, object security policy, property grants, schema-restricted
  properties), and a write freeze stops it.
- Registering identical content writes nothing; a changed registration is an
  audited object update.
- A marking only rises: the entry keeps the least marking that dominates the
  stored and requested ones, under the namespace's lattice.
- `deprecated: true` deregisters; nothing is deleted.
- The response omits the entry when the caller may write but not read it.

Generic object writes refuse the kind, and `source_system: sekai.ontology`
is reserved. Object security activation does not require a `catalog_entry`
policy; in an activated namespace without one, entries are unreadable.

## Curation

Owners and the steward curate an entry's `description`, `tags` and `owners`
through a governed Action (#1686): an Action type with `object_kind:
catalog_entry` and `object_mutation: update`, whose parameters are the
entry's `object_id` and the fields to set (`tags` and `owners` as
comma-separated lists). The Action is admitted, receipted and audited like
any other; the write is an object update carrying the Action's operation id.

- Only a principal listed in `owners`, or the `steward`, may curate; anyone
  else is refused. The submitter must still pass the Action type's submit
  policy.
- Only those fields and `access_marking` change; names, source identity and
  status stay with registration. An entry always keeps an owner.
- The marking only rises. A curation that would lower it is refused;
  lowering is the audited declassify path.
- A curated field stays curated: the entry lists it in `curated`, and later
  registrations keep the curated value instead of the source's.
- Search follows the edit once the index catches up, under the same read
  policy.

## Object types

Object types register themselves: every 60 seconds on each Sekai instance,
the plane keeps one active entry per published
object type, with its `access_marking` and property names, and deprecates
entries for object types no longer published. Namespaces under a write
freeze catch up after it lifts.

Not yet covered: lineage on entries (#1685), and service, release and
environment entries (#1688).
