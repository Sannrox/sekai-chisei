# Governed documents and renditions

Bind document metadata, digest-addressed content references, renditions,
extraction provenance, retention, hold, and deletion. The plane does not store
bytes, open external storage, or run an extractor. See
[ADR 0039](decisions/0039-governed-documents.md) and
[Discussion 771](https://github.com/Sannrox/sekai-chisei/discussions/771).

## Contract

`sekai.governed-document/v1` binds:

- identity `(namespace, document_id)`, owner, and type revision `v1`
- purpose and classification
- a content reference with `scheme=digest`, media type, byte length, and
  `sha256` digest
- optional expiry, hold identity, and bounded metadata

Document content types are `text/plain`, `application/pdf`,
`application/json`, `image/png`, `image/jpeg`, and DOCX
(`application/vnd.openxmlformats-officedocument.wordprocessingml.document`).
Renditions have their own types: `extracted_text` is `text/plain`, `preview`
is PDF or PNG, and `thumbnail` is PNG or JPEG.

A rendition is a derived child. Closed classes are `extracted_text`,
`preview`, and `thumbnail`. Each rendition pins the parent document id, the
parent content digest, its own content reference, and extractor identity plus
profile digest.

An experimental LLM function may bind an `extracted_text` rendition. The
plane still stores no bytes: invoke supplies the text and fail-closes unless
its digest matches the rendition pin. Written objects keep `derived_from`
lineage to the document id, parent content digest, and rendition digest. A
score below the function's `minimum_confidence_micros` parks a
`require_approval` Action instead of writing the object. Scores and
thresholds above `1_000_000` fail closed.

## Operator workflow

```text
sekaictl admin documents admit --document ./document.json --actor analyst
sekaictl admin documents attach-rendition --rendition ./rendition.json --actor analyst
sekaictl admin documents get --namespace records --document-id doc:brief \
  --purpose case-review --field content_ref --field metadata --field renditions \
  --classification-ceiling internal --actor analyst
sekaictl admin documents hold --namespace records --document-id doc:brief \
  --hold-id hold:1 --reason litigation --actor analyst
sekaictl admin documents release-hold --namespace records --document-id doc:brief \
  --hold-id hold:1 --actor analyst
sekaictl admin documents expire --namespace records --document-id doc:brief \
  --actor analyst
sekaictl admin documents delete --namespace records --document-id doc:brief \
  --actor analyst
```

The admitting actor becomes the owner, and only the owner retrieves or
changes the document. The `--document` file is the admission input: the
contract fields above plus an optional `content_digest`, which must match the
content reference. It has no `owner`, `admitted_by`, `admitted_at_ms`, or
`deleted_at_ms`; the server sets those, and a file that carries them is
refused. The `--rendition` file is the attachment input: the rendition
fields without `attached_by` or `attached_at_ms`, which the server sets to the
caller and the attach time. Attaching the same rendition again returns the
stored one; a different rendition under the same id is refused. A retrieve
must present the document purpose.
`--classification-ceiling` can only restrict a sealed principal profile. It
cannot raise clearance.

## Classification

Classification follows the namespace lattice, as Search does
([ADR 0039](decisions/0039-governed-documents.md#amendment-2026-11-10)). A
namespace with an activated lattice admits only its tokens, and a read needs
the caller's sealed ceiling to dominate the marking. A namespace without one
uses `public`, `internal`, `confidential`, and `restricted`; `public` is
visible to the owner without a ceiling. A marking the namespace's rule does
not name is never visible, so keep the fixed tokens your documents use when
you activate a lattice.

Hold blocks expiry and deletion. Deleted or expired documents are
observationally identical to missing documents. Deletion is terminal: the
same `(namespace, document_id)` cannot be re-admitted.

## Failure

| Condition | Result |
| --- | --- |
| Unknown document, foreign owner, mismatched purpose, marking above the ceiling or unknown to the namespace, hidden or unauthorized field | `governed document is unavailable` |
| Active hold during expire or delete | `governed document is held` |
| Unknown media type | `governed document format is unsupported` |
| Unknown type revision or rendition class | `governed document revision is unsupported` |

Unrequested classified fields are omitted. Requesting them fails before any
disclosure. Re-admission of the same live document and content digest is
idempotent. Partial output is discarded.

A document holds at most 32 metadata keys in 8 KiB of encoded metadata and
16 renditions. A content reference names at most 32 MiB.

## RPCs

SQLite and community PostgreSQL store documents and renditions. The stable
RPCs `AdmitGovernedDocument`, `AttachGovernedDocumentRendition`,
`GetGovernedDocument`, `HoldGovernedDocument`, `ReleaseGovernedDocumentHold`,
`ExpireGovernedDocument`, and `DeleteGovernedDocument` mirror the CLI over
gRPC and the HTTP/JSON projection, with the same failure table
(`NOT_FOUND` for unavailable, `FAILED_PRECONDITION` for held, format, and
revision). Each authorizes the namespace before the store: the tenant
context and service-principal scope, shared space, and team-namespace
membership. `GetGovernedDocument` needs read access; the other six need
write access. `AdmitGovernedDocument` takes `GovernedDocumentAdmission` and
`AttachGovernedDocumentRendition` takes `DocumentRenditionAttachment`; both
leave out the fields the server sets. The plane still stores no bytes and
runs no extractor.
