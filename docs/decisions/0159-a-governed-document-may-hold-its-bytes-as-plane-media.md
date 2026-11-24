# ADR 0159: A governed document may hold its bytes as plane media

- Status: accepted
- Date: 2026-11-24
- Owners: @Sannrox
- Issue: https://github.com/Sannrox/sekai-chisei/issues/3041 (#3041)
- Supersedes: none
- Superseded by: none
- Related: [ADR 0039](0039-governed-documents.md), [ADR 0123](0123-governed-media-uploads.md)

## Context

A governed document pins a `digest` content reference, and the bytes stay
with whoever admitted them ([ADR 0039](0039-governed-documents.md)). Plane
media holds file bytes as `media_attachment` objects
([ADR 0123](0123-governed-media-uploads.md)). Before this decision the two did
not meet:

- a document could not name a `sekai-media:` attachment as its content;
- the document's hold, expiry and deletion did nothing to bytes stored in the
  plane;
- the attachment's own marking and the document's classification were two
  authorities over one file.

A platform that wanted to drop its own byte store had to keep a second one.

## Decision

1. A content reference may use the `media` scheme. `media_reference` names a
   complete `sekai-media:` attachment in the document's namespace. Admission
   checks four things: the caller may read the attachment, its stored SHA-256
   equals the declared `digest`, its length equals `byte_length`, and its
   media type equals `media_type`. Media-backed content keeps the 32 MiB
   document limit.
2. Binding makes the document the owner of the bytes. Binding happens before
   the document or rendition is stored, so no stored record names an
   attachment that still answers to its own marking alone. It does two things:
   - it sets the attachment's marking to the document classification;
   - it records the binding (`bound_document_id`, and `bound_rendition_id` for
     a rendition) on the attachment.

   After that, `ReadMedia` on the attachment also requires reading the
   document: owner, live lifecycle, classification and purpose. The purpose
   comes from the request's purpose presentation. A caller who fails gets
   `NOT_FOUND`, as ADR 0123 already does. The attachment's read checks still
   apply to the derived marking. Where the namespace has no lattice, a
   `public` object needs the reader's clearance while a `public` document
   does not; the stricter rule wins, which fails closed.
3. An attachment is bound at most once. The binding is written as an update
   compared against the attachment as read. Binding it to a different
   document or rendition is refused. Binding it again to the same target is a
   retry and succeeds, so re-admission stays idempotent.
4. Reads are decided from the document record at read time. Expiring or
   deleting the document therefore makes the bytes unreadable through both
   the document and the attachment in the transaction that writes the
   document. The bytes then become eligible for `DeleteMedia`. Until then,
   and while the document is held, `DeleteMedia` is refused. A rendition's
   bytes follow its parent: deleting the parent drops its renditions.
5. Binding is written before the record that names it, so an attachment
   whose binding no stored document or rendition names is pending. It stays
   protected from `DeleteMedia` for 10 minutes after the binding was last
   written (`bound_at_ms`), and every retry of the admission writes it again.
   After that the admission is treated as abandoned and the bytes may be
   removed.
6. `digest` references keep their meaning. Their stored record and content
   digest are unchanged, and the plane stores no bytes for them.

## Alternatives considered

- Keep the attachment's own marking alongside the document classification.
  Rejected: two authorities over one file drift apart.
- Copy the bytes into the document record. Rejected: that is a second byte
  store inside the plane, with its own limits.
- Keep bytes out of the plane. Rejected: the platform keeps a separate store
  and credential.
- Record bindings in a new table. Rejected: the attachment object already
  carries its marking and is written under the object policy and audit, so
  the binding needs no schema change on either store.

## Consequences

- `ContentReference` gains `media_reference` (field 5). A stored content
  reference may carry the `media` scheme on SQLite and PostgreSQL; no existing
  value changes.
- An older instance refuses a `media` reference at admission and cannot
  decode a media-backed record, which fails closed.
- During a rolling deploy an older instance's `ReadMedia` checks only the
  attachment. That attachment carries the document classification, but not
  the owner and purpose checks. An older `DeleteMedia` does not consult the
  binding either. Finish the rollout before admitting media-backed documents.

## Validation

`a_document_governs_the_media_it_binds` runs over gRPC on SQLite and on
PostgreSQL. It checks that:

- a mismatched digest, length or media type is refused and binds nothing;
- re-admission is idempotent, and a second document cannot bind the same
  attachment;
- a caller who may read the attachment but not the document gets `NOT_FOUND`;
- live and held documents keep their bytes;
- deletion and expiry hide the bytes of the document and its rendition, then
  allow their removal.
