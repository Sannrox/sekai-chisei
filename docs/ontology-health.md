# Ontology health

`GetOntologyHealth` (#1463) scores one namespace, or every namespace with a
published definition the caller may read, from 0 to 100. It is
`experimental`, so it is rejected unless `SEKAI_EXPERIMENTAL_RPCS=1` or the
`experimental-rpcs` Cargo feature is enabled. Each part has its own score
and up to ten contributing problems. The namespace score is the lowest
available part, and the tenant score the lowest namespace score: one failing
part is never averaged away behind healthy ones.

| Part | Score | Problems |
| --- | --- | --- |
| `freshness` | share of visible datasets not stale | `stale`: a firing late-schedule alert, or a failed latest freshness check |
| `quality` | share of visible datasets passing their checks | `check_failed`: quarantined, or a failed latest row-count, schema, null, unique or predicate check |
| `contract` | share of blocking consumer bindings still satisfied | `member_removed`, `property_removed` (a major revision dropped what the binding names), `unverifiable` (malformed or stale binding digest) |
| `lint` | share of published members without a lint error or warning | the [ontology lint](ontology-lint.md) findings, errors and warnings first; only errors and warnings about a published member lower the score |
| `trust` | unavailable (`not_stored`) | trust scores are computed per object on request by `ScoreObjectTrust` and not stored |
| `access` | share of grants on the namespace and its objects in good standing | `expired`: past its end date; `unreviewed`: no purpose or end date while the namespace policy requires terms, and no recorded exception |

A part with nothing to score scores 100. A part is `available: false` with
an `unavailable_reason` when the server cannot compute it or the caller may
not see it, and it leaves the total. `complete: false` means its inputs were
capped (500 datasets, 10,000 grants of the namespace, or the lint caps), so the score may be
too high.

## Visibility

Scoring a namespace needs read on it; without it the call is refused, and a
tenant-wide call leaves the namespace out. Every part reads as the caller:

- datasets as `ListDatasets` shows them, bound to an object of the namespace;
- contract and lint need read on every published member, as reading the
  published revision does (`not_permitted` otherwise); lint runs as
  `GetOntologyLintReport` with the caller's own request;
- access needs administration of the namespace boundary, and counts each
  grant only when `ListGrants` would show it for its target; a grant it
  would not show makes the part incomplete.

A tenant-wide call scores at most 20 namespaces and says `complete: false`
past that.

## Trends and threshold events

`RecordOntologyHealthSnapshot` stores the part scores of one namespace for
the window holding the current time. The plane runs no scheduler: an
external periodic caller drives it and carries the schedule in each call
(`window_ms`, at least one minute; `retention_ms`, at least one window;
`threshold`, 0-100). Only the namespace's administrator records, so a
snapshot scores what the namespace holds. Problems are not stored.

- Recording is idempotent per (namespace, window): the window's first
  record is kept, and every later or concurrent call, including a retry
  after a crash past commit, returns it with `replay: true` and writes
  nothing.
- A window older than the latest recorded one is refused
  (`FAILED_PRECONDITION`), so the trend stays ordered.
- When the total falls below the threshold, a `below_threshold` event is
  written in the same transaction as the snapshot. Staying below writes no
  further event; recovering and dropping again writes another.
- Snapshots and events whose window started before the retention are pruned
  when a record lands.

`ListOntologyHealthTrend` needs read on the namespace and returns its
snapshots and events, oldest first. A part the reader may not see now is
left out of the snapshot: one that reads `not_permitted` to them on
`GetOntologyHealth`; a dataset part (freshness, quality) scored from a
dataset they may not read; and a contract part scored from a definition
revision they may not read. The snapshot stores which datasets and which
revision fed those parts, never returned. Lint and access count only the
objects, links and grants the recorder could see, which a stored score
cannot prove for anyone else, so they show only to the principal that
recorded the snapshot. Each snapshot's `score` is the lowest of the parts
shown. An event shows
only when the reader may see every part its score was taken from.

## Not covered

Chisei data-quality rules live in the Chisei store and are not read here.
Delivering threshold events anywhere beyond the stored event is out of
scope.
