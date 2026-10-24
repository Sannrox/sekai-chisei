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
| `lint` | share of published members without a lint warning | the [ontology lint](ontology-lint.md) findings, warnings first; only warnings about a published member lower the score |
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

## Not covered

Scores are computed on each call. Stored trends and threshold events are a
separate layer (#1694). Chisei data-quality rules live in the Chisei store
and are not read here.
