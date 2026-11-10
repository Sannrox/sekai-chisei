# ADR 0039: Govern documents as objects with digest-bound renditions

- Status: accepted
- Date: 2026-08-27
- Owners: @Sannrox
- Discussion: https://github.com/Sannrox/sekai-chisei/discussions/771
- Issue: https://github.com/Sannrox/sekai-chisei/issues/688
- Supersedes: none
- Superseded by: none
- Related: [ADR 0031](0031-purpose-bound-reads.md),
  [ADR 0032](0032-hierarchical-classifications.md)

## Context

#678 and #679 shipped purpose-bound reads and hierarchical classifications.
Datasets, content execution, and retention already exist, but they do not bind
a document as a first-class object with metadata, a content reference,
renditions, extraction provenance, hold, expiry, and deletion.

## Decision

A `sekai.governed-document/v1` object is identified by `(namespace, document_id)`.
It pins type revision `v1`, owner, purpose, classification, title, bounded
metadata, and a digest-scheme content reference. The plane does not store
bytes or run extractors.

A rendition is a derived child with a closed class (`extracted_text`,
`preview`, `thumbnail`). It pins the parent document id, parent content
digest, its own content reference, and extractor identity plus profile digest.

Hold blocks expiry and deletion. Deleted or expired documents are
observationally identical to missing documents. Deletion is terminal; the
same identity cannot be re-admitted. Retrieval is field-bounded:
unrequested classified fields are omitted; requesting a field above the
caller ceiling, a mismatched purpose, a foreign owner, or an unknown field
fails before disclosure. Re-admission of the same live document and content
digest is idempotent.

SQLite is the reference store. Community PostgreSQL shares the same
persistence and experimental RPCs (#1325). The plane still stores no bytes
and runs no extractor.

## Amendment 2026-10-09

#1325 ports admit, rendition, retrieve, hold, expire, and delete onto
community PostgreSQL and exposes those operations as experimental
`SekaiService` RPCs. managed media sets keep bytes and extractors in the
platform; this plane records digest-addressed references only.

## Amendment 2026-11-10

#2245 moves document classification onto the namespace classification
lattice, the rule Search and the embedding index already use
([ADR 0032](0032-hierarchical-classifications.md)). This is the move
[ADR 0007](0007-provisional-classification-markings.md) expects for its
provisional markings.

- A namespace with an activated lattice admits only its tokens, matched
  exactly. A read needs the caller's sealed ceiling to dominate the marking
  in that lattice. Trusted service principals stay the exception.
- A namespace without a lattice keeps the fixed markings
  `public < internal < confidential < restricted`, matched without regard to
  case. `public` stays visible to the owner without a ceiling. The default
  lattice names the same four tokens in the same order, so no stored value
  changes and no data migration runs on SQLite or PostgreSQL.
- A stored fixed marking that an activated lattice does not name is
  unknown, and an unknown marking is never visible, trusted principals
  included. Operators who activate a lattice keep the fixed tokens their
  documents use, or re-admit them under a new identity.
- A requested `classification_ceiling` must be a token of the same rule and
  only restricts: the read also needs it to dominate the marking.

Until every instance runs this version, an older instance still compares a
fixed marking by the fixed order in an activated namespace, and hides a
custom token, which it cannot parse.

Admission takes `GovernedDocumentAdmission`, not the stored record. It has
no owner, `admitted_by`, `admitted_at_ms`, or `deleted_at_ms`: the server
sets the owner and `admitted_by` to the caller and stamps the time. Its
field numbers match `GovernedDocument`, so a request encoded by an older
client still decodes. The server ignores the stored-record fields it carries.

## Alternatives considered

Treating documents as blobs with sidecar metadata was rejected because
lifecycle and markings would drift from the object. Independent rendition
identities were rejected because a derived view could outlive its source.
Fetching or extracting content in the control plane was rejected because
credentials and remote failure would become authority.

## Consequences

Operators admit documents, attach renditions, retrieve authorized fields, and
apply hold, expiry, and deletion through `sekaictl admin documents`. Image
assets are recorded in [ADR 0050](0050-governed-images.md).

## Validation

Deterministic fixtures cover authorized admit, extraction, bounded retrieval,
hold, expiry, deletion, idempotent replay, hidden-field denial, mismatched
purpose, foreign ownership, unknown formats, unsupported revisions, and
corrupt digests.
