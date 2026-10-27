# Trust scores

A trust score is a computed 0 to 100 confidence for one object, with the
reasons that produced it. It is an explained points table, not a model, and
it is experimental: the RPCs below need `SEKAI_EXPERIMENTAL_RPCS=1` or the
`experimental-rpcs` Cargo feature (see [rpc-maturity.md](rpc-maturity.md)).

## Scoring rule

Each namespace has at most one `sekai.trust-scoring-rule/v1`:

```json
{
  "contract_version": "sekai.trust-scoring-rule/v1",
  "namespace": "acme",
  "base": 60,
  "source_penalties": {"delayed": 15, "blocked": 40, "unavailable": 30},
  "expected_freshness_ms": 86400000,
  "stale_penalty": 20,
  "verification_property": "verified_by",
  "verified_bonus": 25,
  "agreement_relation": "corroborates",
  "agreement_bonus": 10,
  "conflict_relation": "contradicts",
  "conflict_penalty": 10
}
```

| Factor | Signal | Effect |
| --- | --- | --- |
| `base` | always | `base` points |
| `source` | health class of the source that syncs the object (`sync_source_instance`, `sync_type_digest`); a source the plane cannot read is `unavailable` | minus `source_penalties[class]` |
| `freshness` | `updated` older than `expected_freshness_ms` | minus `stale_penalty` |
| `verification` | a non-empty `verification_property` value | plus `verified_bonus` |
| `agreement` | visible objects linking to it with `agreement_relation` | plus `agreement_bonus` each |
| `conflict` | visible objects linking to it with `conflict_relation` | minus `conflict_penalty` each |

A zero or empty field turns a factor off. The total is clamped to 0..=100.

`PutTrustScoringRule` is credential-admin only. It stores a new revision
when `expected_revision_digest` names the current revision (empty for the
first rule), and fails with `FAILED_PRECONDITION` otherwise. Storing the
current revision again is a no-op, so a retry succeeds. Each revision is
written through the audited object path as a reserved governance object
(`trust_scoring_rule`): the object change log records the actor, time, and
old and new revision digest and version in the same transaction as the
rule. Generic object reads and writes cannot see or change it.
`GetTrustScoringRule` returns the current revision to anyone with read access
to the namespace boundary.

## Scoring objects

`ScoreObjectTrust` evaluates one page of an object set through
`EvaluateObjectSet`, so members, hidden properties and paging are exactly
what the caller could read. Linked objects are checked with the request's
purpose, as members are. It scores each member, drops members below
`min_score`, and with `order_by_score` sorts highest first, then by object
id. Every signal is read as the caller: a hidden verification property, a
hidden linking object adds nothing, and a caller outside the namespace sees
every source as `unavailable`, as `ReportSourceHealth` does. One request reads
at most 10,000 link rows for the agreement and conflict factors, then fails
with `RESOURCE_EXHAUSTED`; a factor with no weight reads none.

Not yet covered: per-property scores, filtering search and agent retrieval
by score, and requiring a minimum score before an Action.
