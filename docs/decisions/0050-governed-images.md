# ADR 0050: Govern image assets with digest-bound renditions and annotations

- Status: accepted
- Date: 2026-08-27
- Owners: @Sannrox
- Discussion: https://github.com/Sannrox/sekai-chisei/discussions/798
- Issue: https://github.com/Sannrox/sekai-chisei/issues/696 (#696)
- Supersedes: none
- Superseded by: none
- Related: [ADR 0039](0039-governed-documents.md)

## Context

ADR 0039 binds documents as objects with digest-bound renditions. Images still
need a first-class object that binds original content, thumbnails, annotations,
derivation provenance, and lifecycle without storing bytes or treating binary
as authority.

## Decision

A `sekai.governed-image/v1` object is identified by `(namespace, image_id)`.
It pins type revision `v1`, owner, purpose, classification, title, bounded
metadata, and a digest-scheme content reference. The plane does not store
bytes or run a renderer.

A rendition is a derived child with a closed class (`thumbnail`,
`derived_metadata`). It pins the parent image id, parent content digest, its
own content reference, and extractor identity plus profile digest.

An annotation is a typed child effect with a closed class (`region`, `label`).
It pins the parent image id, parent content digest, and a bounded JSON
payload. Annotations never carry binary content.

Hold blocks expiry and deletion. Deleted or expired images are
observationally identical to missing images. Deletion is terminal. Retrieval
is field-bounded. Requesting `bytes` or `binary`, a hidden or unknown field,
a mismatched purpose, a foreign owner, or a field above the caller ceiling
fails before disclosure. Re-admission of the same live image and content
digest is idempotent.

SQLite is the reference store. PostgreSQL stays unavailable.

## Alternatives considered

Treating images as document renditions was rejected because annotations and
thumbnail lineage are first-class. Storing or fetching bytes was rejected
because credentials and remote failure would become authority. Client-side
masking was rejected because derived views would still see the values.

## Consequences

Operators admit images, attach thumbnails, derived metadata, and annotations,
retrieve authorized fields, and apply hold, expiry, and deletion through
`sekaictl admin images`. Document objects remain ADR 0039.

## Validation

Deterministic fixtures cover original, thumbnail, annotation, derived
metadata, binary denial, metadata denial, replay, hidden fields, unknown
formats, unsupported revisions, and corrupt digests.
