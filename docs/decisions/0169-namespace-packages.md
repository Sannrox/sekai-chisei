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
2026-11-24 (decisions 1 to 8), amendments A, B and C on 2026-11-25, and
amendments D, E and F (dataset content) on 2026-11-26.

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
9. A package never carries credentials, run history, receipts or audit
   entries. It carries rows only for the datasets the exporter opts into
   content (decision 13); a verifier refuses content on any other entry.
10. Install verifies the package before any write and opens the
    definitions as a proposal in the target namespace. The installation is
    `pending_definitions` until that proposal applies, then `installed` when
    the applied revision's digest equals the ontology digest, or `diverged`
    by name when it does not (amendment B). An approved proposal whose
    definitions no longer match the package digest is refused, not applied
    partially: a merge publishes exactly the proposal's candidate and is
    refused as stale once its branch moves.
11. `InstallNamespacePackage` (experimental) needs write access to the
    target namespace. Its request maps every dataset entry by id, and an
    unmapped entry or a mapping with no entry is refused by name:
    - an output names a new dataset id and an object in the target
      namespace to bind it to, since a dataset reaches a namespace only
      through its object. The dataset is created with the entry's name,
      columns and partition keys under the caller's dataset write grant;
    - an input names an existing dataset bound in the target namespace that
      the caller may read in every column; its schema digest must equal the
      entry's, or it is refused by name.
    The definitions open as proposal `package/{name}/v{version}`, only into
    a namespace with no published definitions: merging into one that holds
    definitions is a non-goal. A package without definitions opens none and
    is `installed` at once.
12. One installation is stored per `(namespace, package name)`, with its
    resources, the package digest, version, source namespace and signer.
    Its status is derived from the proposal on read, not stored. Install
    is idempotent per `(package digest, target namespace)`: the same package
    returns the stored installation, and a later version upgrades it
    (decision 14). Each write is idempotent and the record is written last,
    so a retry after a crash converges, and the first record stored wins a
    race.

13. Dataset content (amendments D, E and F). The export request names, of the
    selected datasets, those whose rows the package carries.
    - The rows of the dataset's latest version go inline in its
      `dataset_version` entry, which sets `content_included`. Its document
      adds `content_digest`, SHA-256 over the canonical rows, and the rows to
      the definition. The entry digest stays the schema digest, and the
      package digest and signature cover the rows. All rows of a package
      together are at most `MAX_PACKAGE_CONTENT_BYTES` (2 MiB of canonical
      JSON, so a package fits one gRPC message); over it, export is refused
      with `namespace_package_content_too_large`. No separate content stream
      in v1.
    - Content needs an export grant on the namespace, as `ExportDatasetVersion`
      does, beyond read; without one the export is refused by name.
    - A column whose classification the exporter's allowed egress may not
      receive stays in the schema and is absent from the rows, counted as
      `dataset_column` in the withheld list without ids. A restricted column
      the exporter may not read is withheld the same way, and a dataset whose
      bound object type has cell grants cannot carry content.
    - Rows are checked against the columns and types (`int`, `float`, `bool`;
      an empty value is null) at export, at verification and at install, and
      a mismatch is refused by name.
    - Install appends the rows to the created dataset as one new version
      under the caller's dataset write grant. Source version ids are not
      carried. Content apply is idempotent per `(package digest, target
      dataset)`: a retry appends only to a dataset without versions, and a
      dataset whose latest version holds other rows is refused as changed
      outside the installation. Upgrade appends only when the content digest
      changed (decision 14).

14. Upgrade (#3093 decision 8). Installing a later version of an installed
    package upgrades its installation; an earlier version is refused by name.
    - Definitions open as proposal `package/{name}/v{version}` against the
      published head, only while that head reproduces the installed ontology
      digest; otherwise they changed outside the installation and are refused.
      Unchanged definitions open nothing and keep the merged proposal. An
      installed proposal still open is refused until it merges or closes, so
      two versions are never under review at once; a closed one installs as
      into an empty namespace. The definitions are one resource: a member the
      new version drops is removed through that proposal's review.
    - A dataset an earlier version installed keeps its id and binding; the
      request may leave it unmapped and may not move it. The installation
      records each dataset's schema digest and, for carried rows, a digest
      of what its latest version held, ignoring row order. A changed
      definition updates the dataset under the dataset write grant only
      while its schema still has the recorded digest.
    - A dataset version holds every row appended so far, so carried rows are
      appended as one new version holding the rows the latest version lacks,
      only while that version still has the recorded digest. A version that
      drops rows is refused: a dataset only takes appended rows.
    - New entries install as in decision 11. Resources the new version no
      longer carries stay in place and are listed as retained.
    - The record is replaced last, only while it still equals the record the
      upgrade read, so of two racing upgrades the first wins and a retry
      converges.

`ExportNamespacePackage` (experimental) builds and signs the package from the
published head. It needs read access to the namespace, as a definition export
does. `GetNamespacePackageInstallation` reads an installation with its status
under namespace read access. Delivery is layered: this format and the export
first, then install with input mapping and installation records, then opt-in
dataset content (decision 13), then upgrade of an existing installation
(decision 14).

## Consequences

- One versioned format the core verifies on both ends; a composing platform
  drops its own bundle schema.
- Carried rows install through the governed append path, so the target's
  dataset write grant applies. Datasets over the content bound still move
  as definitions only.
- An export of a namespace whose definitions are partly unreadable is signed
  and verifiable but partial, and says so through the withheld counts.
- Installations live in `sekai_namespace_package_installations` (SQLite on
  open, PostgreSQL migration 186). An older plane ignores the table;
  rolling back leaves the installed proposal and datasets in place, as
  ordinary resources.
- A definitions proposal that is closed instead of merged leaves its
  installation `pending_definitions`; reinstalling the same package returns
  that installation, and a later version installs as into an empty
  namespace.
- An installation record written before upgrade records no digests, so an
  upgrade of it refuses a changed dataset definition, or new rows over
  existing ones, as changed outside the installation. No release shipped
  such records.

## Rejected alternatives

- Extend namespace snapshots: their facts are replicas without write
  authority by design (ADR 0029).
- A raw store dump: it bypasses policy and audit and is tied to one backend.
- An `object_set` kind in v1: it has no install path (amendment A).
- Carry governed transforms: installing them is out of v1 (amendment C).
