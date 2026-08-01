# Epistemic context operations report

`QueryOperationStatistics` includes a bounded `epistemic` projection for
operators who need to understand context use and measured outcome impact. The
projection is namespace-authorized by the same check as the rest of the
statistics response.

The report is deliberately aggregate-only. It never returns prompts, claims,
evidence references or digests, actors, credentials, or labels derived from
source identity. Decision, evidence-status, and lifecycle-status labels are
fixed enums, so the report cannot create an unbounded label set.

## Accounting semantics

`context_receipts` counts receipts with a `ContextGoverned` event in the query
window. `accounted_receipts` counts those carrying the versioned epistemic
context-accounting marker and descriptor counters. Older or incomplete receipts are counted as
`missing_receipts`; they are not treated as zero usage.

`accounting_status` is one of:

- `available`: all context receipts are accounted and the Kioku report reads
  were available;
- `no_observations`: the window contains no context receipts;
- `partial`: at least one context receipt is missing descriptor accounting;
- `unavailable`: a backend report read was unavailable or exceeded the bounded
  observation limit.

Decision counts use the fixed buckets `included`, `qualified`, `held_out`,
`excluded`, and `escalated`. Evidence status counts use `supported`,
`contested`, `insufficient`, and `unknown`. Lifecycle status counts use
`current`, `stale`, `retracted`, `superseded`, and `unknown`.

`context_bytes_total` and `context_tokens_total` are the prepared system and
complete message measurements, including tool-call identifiers, names, and
arguments. Tokens are a deterministic estimate, not a provider billing claim.
`projection_latency_ms_total` sums the bounded
pipeline projection measurements, and `projection_observations` is its
denominator. `truncated_count` counts context receipts whose source projection
was truncated.

Evaluation observations and passes count only outcome events that include the
canonical boolean `passed` field. Treatment/control samples and pass counts
come from Kioku outcome observations. The treatment-control delta is a pass
rate difference in micro-units (`treatment - control`) and is present only when
both arms have at least one sample. It is an observational diagnostic, not a
causal claim.

`reassessment_events` counts evidence reassessment lifecycle events and
`retirement_events` counts outcome-regression retirements. Lifecycle actors and
reasons are intentionally omitted.

The SQLite and PostgreSQL community stores use backend-specific, bounded
queries for receipts, lifecycle events, outcomes, and active promotions. If a
backend cannot provide a report surface, the response remains readable and
sets `accounting_status=unavailable` instead of failing a health or statistics
request because no epistemic context exists.
