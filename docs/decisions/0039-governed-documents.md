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

SQLite is the reference store. PostgreSQL stays unavailable.

## Alternatives considered

Treating documents as blobs with sidecar metadata was rejected because
lifecycle and markings would drift from the object. Independent rendition
identities were rejected because a derived view could outlive its source.
Fetching or extracting content in the control plane was rejected because
credentials and remote failure would become authority.

## Consequences

Operators admit documents, attach renditions, retrieve authorized fields, and
apply hold, expiry, and deletion through `sekaictl admin documents`. Follow-up
work may add image assets (#696) after this object contract exists.

## Validation

Deterministic fixtures cover authorized admit, extraction, bounded retrieval,
hold, expiry, deletion, idempotent replay, hidden-field denial, mismatched
purpose, foreign ownership, unknown formats, unsupported revisions, and
corrupt digests.
