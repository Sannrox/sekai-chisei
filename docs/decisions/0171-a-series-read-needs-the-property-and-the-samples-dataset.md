# ADR 0171: A series read needs the property and the samples dataset

- Status: accepted
- Date: 2026-11-26
- Owners: @Sannrox
- Discussion: none, resolved in shaping on Issue #3472
- Issue: #3472
- Supersedes: [ADR 0161](0161-series-samples-as-datasets-with-a-governed-series-read.md) for its access clause only
- Superseded by: none
- Related: [ADR 0027](0027-explicit-property-grants.md),
  [ADR 0030](0030-row-scoped-query-access.md),
  [ADR 0071](0071-rpc-maturity.md),
  [ADR 0164](0164-reads-withhold-what-a-readers-egress-may-not-receive.md)

## Context

ADR 0161 stores series samples as governed datasets and lets an object's
`series` property name one series. Its access clause let anyone who may read
the property read the series, with no read of the samples dataset. That makes
the object a way around the dataset: a marking, column grant or egress limit
on the samples dataset would not hold for a reader who reaches the samples
through an object pointing at them.

## Decision

1. `ReadObjectSeries` (experimental) needs both reads, and either refusal
   refuses it:
   - the object is read through `GetObject`'s path, so visibility, markings,
     purpose and property grants match it, and the `series` property must
     survive that read;
   - the samples dataset is read like any dataset read: its grant and
     markings, every sample column (`series_id`, `timestamp`, `value`)
     readable under the column grants of its binding object, and every
     sample column's classification released to the reader's egress.
2. A property the reader may not read is absent, so the read fails
   `NOT_FOUND` "series not found", the same as an unset property. Every
   refusal on the dataset side, including a samples dataset that does not
   exist, is the same `PERMISSION_DENIED` "series dataset access denied",
   decided before any row is read. A refusal never carries sample values or
   counts.
3. A quarantined samples dataset fails `series_dataset_quarantined` instead
   of serving its last healthy version.
4. A stored sample whose timestamp is not an integer or whose value is not a
   finite number fails `series_sample_invalid` rather than being skipped.
5. Both stores index samples by `(dataset_id, series_id, timestamp)`, partial
   on rows that carry a `series_id`. The index is guarded: a row with
   malformed JSON, or on PostgreSQL a non-numeric `timestamp`, is left out
   rather than failing its insert or the index build on upgrade.

The rest of ADR 0161 stands, with the caps it left open set as constants:
10,000 points per read (a larger target is lowered) and 1,000,000 samples
scanned (a larger range fails `series_scan_cap_exceeded`).

## Alternatives considered

- Property access alone (ADR 0161). Rejected: a restriction on the samples
  dataset could be bypassed through an object that points at it.
- A per-property opt-out from the dataset check. Rejected in shaping: it
  brings the bypass back as configuration.
- Distinct refusals for a missing dataset, a missing grant and a withheld
  column. Rejected: the difference tells a reader what exists behind a
  refusal.
- Serving a quarantined dataset's last healthy version. Rejected for now: it
  needs a version-aware index, and refusing by name is honest about the
  state.

## Consequences

- A console that shows a series needs its readers granted on the samples
  dataset as well as the property.
- Every row with a `series_id` adds one index entry on write. On PostgreSQL
  every row insert evaluates the partial index predicate.
- Old clients do not call the new RPC; nothing else changes on the wire.

## Validation

- `read_object_series_needs_the_property_and_the_samples_dataset`: points for
  a reader of both, bucketing past the target, "series not found" for an
  unset or grant-withheld property, and the same denial for a missing
  dataset, a withheld sample column and an egress limit.
- `sqlite_reads_one_series_in_range` and `postgres_reads_one_series_in_range`:
  range, order, other series, the scan cap, an invalid sample and quarantine.
- `sqlite_series_read_seeks_the_series_index_in_order` and
  `postgres_series_read_can_seek_the_series_index`: the read is one range scan.
