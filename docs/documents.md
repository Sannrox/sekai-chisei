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

A rendition is a derived child. Closed classes are `extracted_text`,
`preview`, and `thumbnail`. Each rendition pins the parent document id, the
parent content digest, its own content reference, and extractor identity plus
profile digest.

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

The admitting and retrieving actor must be the registered owner. A retrieve
must present the document purpose. `--classification-ceiling` can only
restrict a sealed principal profile. It cannot raise clearance.

Hold blocks expiry and deletion. Deleted or expired documents are
observationally identical to missing documents. Deletion is terminal: the
same `(namespace, document_id)` cannot be re-admitted.

## Failure

| Condition | Result |
| --- | --- |
| Unknown document, foreign owner, mismatched purpose, hidden or unauthorized field | `governed document is unavailable` |
| Active hold during expire or delete | `governed document is held` |
| Unknown media type | `governed document format is unsupported` |
| Unknown type revision or rendition class | `governed document revision is unsupported` |

Unrequested classified fields are omitted. Requesting them fails before any
disclosure. Re-admission of the same live document and content digest is
idempotent. Partial output is discarded.

SQLite stores documents and renditions. PostgreSQL surfaces stay unavailable.
