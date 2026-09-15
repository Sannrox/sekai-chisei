# Research: incremental governed-transform envelope

Issue: [#879](https://github.com/Sannrox/sekai-chisei/issues/879)
Follow-up: [#880](https://github.com/Sannrox/sekai-chisei/issues/880)
Date: 2026-09-15
Status: **envelope published**
Decision: [ADR 0074](../decisions/0074-plane-owned-transforms.md)

In-process `projection` over dataset rows. Not an engine, table format, or
cluster pick. SQLite is the community measurement vehicle.

## Fixture

Five chained transforms, 200 input rows then a 1% append (2 rows). Deterministic
test: `five_transform_pipeline_is_incremental` in
`src/db/governed_transform.rs`.

| Metric | Result |
| --- | --- |
| Full first-stage rows_in | 200 |
| Incremental first-stage rows_in after 1% append | 2 |
| Final pipeline output rows | 202 |
| Quality quarantine | previous output remains queryable |

No object identity is minted. Credentials in definitions are rejected.
