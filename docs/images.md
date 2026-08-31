# Governed images, renditions, and annotations

Bind image metadata, digest-addressed content references, thumbnails, derived
metadata, annotations, derivation provenance, retention, hold, and deletion.
The plane does not store bytes, open external storage, or run a renderer. See
[ADR 0050](decisions/0050-governed-images.md) and
[Discussion 798](https://github.com/Sannrox/sekai-chisei/discussions/798).

## Contract

`sekai.governed-image/v1` binds:

- identity `(namespace, image_id)`, owner, and type revision `v1`
- purpose and classification
- a content reference with `scheme=digest`, image media type, byte length, and
  `sha256` digest
- optional expiry, hold identity, and bounded metadata

A rendition is a derived child. Closed classes are `thumbnail` and
`derived_metadata`. Each rendition pins the parent image id, the parent
content digest, its own content reference, and extractor identity plus
profile digest.

An annotation is a typed child. Closed classes are `region` and `label`. Each
annotation pins the parent content digest and a bounded JSON payload. It
never carries binary content.

## Operator workflow

```text
sekaictl admin images admit --image ./image.json --actor analyst
sekaictl admin images attach-rendition --rendition ./thumbnail.json --actor analyst
sekaictl admin images attach-annotation --annotation ./note.json --actor analyst
sekaictl admin images get --namespace records --image-id img:site \
  --purpose case-review --field content_ref --field metadata --field renditions \
  --field annotations --classification-ceiling internal --actor analyst
sekaictl admin images hold --namespace records --image-id img:site \
  --hold-id hold:1 --reason litigation --actor analyst
sekaictl admin images release-hold --namespace records --image-id img:site \
  --hold-id hold:1 --actor analyst
sekaictl admin images expire --namespace records --image-id img:site --actor analyst
sekaictl admin images delete --namespace records --image-id img:site --actor analyst
```

The admitting and retrieving actor must be the registered owner. A retrieve
must present the image purpose. `--classification-ceiling` can only restrict a
sealed principal profile. It cannot raise clearance.

Hold blocks expiry and deletion. Deleted or expired images are
observationally identical to missing images. Deletion is terminal: the same
`(namespace, image_id)` cannot be re-admitted.

## Failure

| Condition | Result |
| --- | --- |
| Unknown image, foreign owner, mismatched purpose, hidden or unauthorized field, bytes/binary request | `governed image is unavailable` |
| Active hold during expire or delete | `governed image is held` |
| Unknown media type | `governed image format is unsupported` |
| Unknown type revision, rendition class, or annotation class | `governed image revision is unsupported` |

Unrequested classified fields are omitted. Requesting them fails before any
disclosure. Re-admission of the same live image and content digest is
idempotent. Partial output is discarded.

SQLite stores images, renditions, and annotations. PostgreSQL surfaces stay
unavailable.
