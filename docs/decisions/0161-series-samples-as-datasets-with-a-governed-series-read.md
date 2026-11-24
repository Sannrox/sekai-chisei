# ADR 0161: Series samples as datasets with a governed series read

- Status: accepted
- Date: 2026-11-24
- Owners: @Sannrox
- Issue: https://github.com/Sannrox/sekai-chisei/issues/3088 (#3088)
- Supersedes: none
- Superseded by: none
- Related: [ADR 0027](0027-explicit-property-grants.md), [ADR 0030](0030-row-scoped-query-access.md), [ADR 0046](0046-bounded-source-health.md)

## Context

Consoles need to show measurements over time for objects. There is no
governed way to store time series samples, and no core read serves a series:

- object properties have no series type;
- datasets are governed, versioned row stores, but `QueryRows` reads rows by
  dataset id with no downsampling and no object-scoped access;
- an object type can already be bound to a dataset as its datasource.

Samples are many, small and append-mostly. A separate store would need its
own markings, retention, lineage and access checks, which datasets already
have. Reading a dataset directly gives the caller every series in it and
returns raw rows a console cannot draw at scale.

## Decision

1. Samples are stored as datasets whose rows are
   `(series_id, timestamp, value)`, governed like any other dataset: versions,
   markings, health, lineage and retention apply unchanged.
2. An object type may declare a `series` property. Its definition names the
   samples dataset, and its value on each object is a `series_id` in that
   dataset.
3. Access to a series follows access to the object: a caller may read the
   series exactly when it may read that property on that object
   ([ADR 0027](0027-explicit-property-grants.md),
   [ADR 0030](0030-row-scoped-query-access.md)). No dataset-level read grant
   is needed or implied.
4. The governed series read takes an object, a property, a time range and a
   target point count. It returns at most the target number of points, and
   the plane caps the target. When the range holds more samples than the
   target, it returns one point per fixed-width time bucket with the bucket
   start, count, minimum, maximum and mean, so spikes survive downsampling.
   Otherwise it returns the samples as they are.
5. The read is bounded: a cap on points returned and a cap on samples
   scanned. A read that would exceed the scan cap fails with a named reason
   instead of returning a partial series.
6. In the first version, values are floating-point numbers and timestamps are
   milliseconds. Categorical series need a separate decision.

## Alternatives considered

- A dedicated time-series store. Rejected: a second governance path for
  markings, retention and access.
- Series as array-valued object properties. Rejected: unbounded object size
  and a new object version for every sample.
- Serving series through `QueryRows`. Rejected: no downsampling, and the
  caller would need read access to the whole dataset rather than to one
  object's series.

## Consequences

- `series` is a new property type, so ontology export and import, linting and
  generated clients must accept it. Old clients see an unknown property type.
- Ingest uses the existing dataset write paths. There is no new ingest
  protocol.
- The feature Issue for the read decides the cap values and the index the
  scan needs. No code ships with this decision.

## Validation

When the read is built:

- a caller who may read the object's `series` property gets its points, and
  one who may not gets the same refusal as for the property;
- a caller with no grant on the samples dataset still reads the series it may
  see on the object;
- a range with more samples than the target returns at most the target number
  of bucketed points with count, minimum, maximum and mean;
- a read past the scan cap fails with its named reason.
