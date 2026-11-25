# ADR 0169: A namespace package is a signed manifest of its governed resources

- Status: accepted
- Date: 2026-11-25
- Owners: @Sannrox
- Issue: https://github.com/Sannrox/sekai-chisei/issues/3093 (#3093)
- Supersedes: none
- Superseded by: none
- Related: ADR 0029

## Context

A tenant move needs one inventory of a namespace's governed resources that
the core produces and can verify on install. Definitions already move as a
signed `sekai.definition-package/v1` envelope and import as a proposal
(#1700). Datasets and object sets export as digested streams, with no import
of dataset content. Namespace snapshots (ADR 0029) share facts as replicas
without write authority, so they cannot install resources into another
tenant.

The maintainer accepted the `sekai.namespace-package/v1` decision on #3093 on
2026-11-24 (decisions 1 to 8) and amendments A, B and C on 2026-11-25.

## Decision

1. The unit is one namespace. A package is installed into a namespace the
   target tenant already owns.
2. A package is a `sekai.namespace-package/v1` manifest in canonical JSON:
   a name, a version, the ontology digest, one entry per resource, and a
   withheld list. The name is 1 to 128 bytes of `a-z`, `0-9`, `.`, `_`, `-`.
   The version is an integer of at least 1, so installations order upgrades.
3. An entry has `kind`, `id`, `role` (`output` or `input`), `digest`,
   `content_included`, and `document_json`, the canonical JSON of what an
   output creates (empty for an input). Entries are sorted by kind, then id.
   Kinds in v1 are `definition_package` and `dataset_version`; an installer
   refuses any other kind by name (amendment A drops `object_set`: the core
   stores no object set as a resource with an id).
4. The one `definition_package` entry (`id` `definitions`) carries the
   published definition members the caller may read as a definition package.
   Its digest is that package's namespace-free digest. The ontology digest is
   the same value: the revision digest is bound to its namespace and parent,
   so the namespace-free digest is the one a target reproduces when it
   applies the members. Governed transforms are not carried in v1: a dataset
   a transform produces is packaged as a definition, and reinstalling its
   transform is out of v1 (amendment C).
5. A `dataset_version` output is a dataset the exporting caller selects
   (amendment C). Each must be bound to an object in the namespace and
   readable in every column; one that is not is refused by name, and a
   missing dataset is refused with the same message. Its document is the
   name, the columns in order (name, type, classification), and the partition
   keys. Its digest is the schema digest over columns and partition keys,
   without the name, so an installer can match a mapped input under another
   name.
6. An `input` is a resource a carried resource depends on but the package
   does not carry; the installer maps it and checks its kind and schema
   digest (decision 7). With transforms out of v1, no carried resource
   depends on an uncarried dataset, so v1 export emits no inputs. The role
   ships in v1 so adding inputs later does not change the format.
7. The withheld list counts, by member kind, the definition members the
   caller may not read, never their ids. Every count is positive, and the
   list is sorted by kind. This differs from ADR 0029, whose snapshots record
   no hidden counts: #3093 decision 3 requires the counts so an installer
   knows the package is partial.
8. The package digest is SHA-256 over the whole canonical manifest. The
   envelope signs it, with provenance (source namespace, source revision,
   export time), using the definition package signature under this contract
   and the same site key (`SEKAI_DEFINITION_PACKAGE_SIGNING_KEY`,
   `SEKAI_DEFINITION_PACKAGE_SIGNER`). Verification recomputes every entry
   digest, the ontology digest, and the package digest, then checks the
   signature, before anything is trusted. Refusals name a reason:
   `namespace_package_unverified`, `namespace_package_tampered`, or
   `namespace_package_incompatible`.
9. A package never carries credentials, run history, receipts, audit entries
   or rows. `content_included` is false in this layer, and a verifier refuses
   an entry that sets it.
10. Install (later layer) verifies the package before any write and opens the
    definitions as a proposal in the target namespace. The installation is
    `pending_definitions` until that proposal applies, then `installed` when
    the applied revision's digest equals the ontology digest, or `diverged`
    by name when it does not (amendment B). An approved proposal whose
    definitions no longer match the package digest is refused, not applied
    partially.

`ExportNamespacePackage` (experimental) builds and signs the package from the
published head. It needs read access to the namespace, as a definition export
does. Delivery is layered: this format and the export first, then install
with input mapping and installation records, then opt-in dataset content
(rows the caller's egress may not receive are withheld and counted), then
upgrade of an existing installation (decision 8).

## Consequences

- One versioned format the core verifies on both ends; a composing platform
  drops its own bundle schema.
- Installing data still needs a governed dataset-version import path (the
  content layer).
- An export of a namespace whose definitions are partly unreadable is signed
  and verifiable but partial, and says so through the withheld counts.

## Rejected alternatives

- Extend namespace snapshots: their facts are replicas without write
  authority by design (ADR 0029).
- A raw store dump: it bypasses policy and audit and is tied to one backend.
- An `object_set` kind in v1: it has no install path (amendment A).
- Carry governed transforms: installing them is out of v1 (amendment C).
