# Registered Iceberg and Parquet projections

Query typed authorized projections over registered Iceberg tables and Parquet
files. The plane does not open external storage, hold source credentials, or
run a general compute engine. See
[ADR 0036](decisions/0036-open-table-projections.md) and the
`projection` class in
[Discussion 746](https://github.com/Sannrox/sekai-chisei/discussions/746).

## Contract

`sekai.open-table-source/v1` binds:

- format: `iceberg` or `parquet`
- schema revision: `v1`
- schema digest and snapshot digest
- namespace, owner, and column markings
- a locally admitted row snapshot whose digest matches the registration

Query is the `projection` class of `sekai.governed-transform-execution/v1`.
Identity is `(profile_version, class, namespace, definition_digest, input_digest)`.
The projection receipt names source, revision, snapshot digest, authorized
columns, and a content digest of the returned rows. Raw hidden fields and
engine internals never enter the receipt.

## Operator workflow

Register a source document, admit the matching snapshot, then query:

```text
sekaictl admin tables register --source ./source.json --actor analyst
sekaictl admin tables admit-snapshot --snapshot ./snapshot.json --actor analyst
sekaictl admin tables query --source-id iceberg:events \
  --column id --column city --classification-ceiling internal --actor analyst
```

The registering and querying actor must be the registered owner. A later
snapshot is a new digest: the same owner re-registers the expected digest,
which invalidates any previously admitted snapshot, then admits again. A
different actor cannot take over an existing source id.

`--classification-ceiling` can only restrict a sealed principal profile. It
cannot raise clearance.

## Failure

| Condition | Result |
| --- | --- |
| Unknown source, foreign owner, hidden or unauthorized column, sensitive predicate | `open table projection is not admitted` |
| Registered source without a snapshot | `open table snapshot is unavailable` |
| Digest mismatch, row/schema corruption | `open table snapshot is corrupt` |
| Unknown format or schema revision | `open table revision is unsupported` |

Hidden fields that were not requested are omitted. Requesting them fails
before any row is returned. The same snapshot digest always yields the same
authorized projection. Partial output is discarded.

SQLite stores registrations and snapshots. PostgreSQL surfaces stay
unavailable.
