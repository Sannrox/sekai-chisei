# Authorized consumer impact

`ReportDefinitionConsumerImpact` joins `CompareDefinitionRevisions` to
explicit `sekai.definition-consumer-binding/v1` objects. Bindings may name
`object_type`, `function`, `transform`, and `policy` members, and the
report lists every visible hit across those kinds. The plane does not
scan repositories or infer undeclared dependents.

Registration, refresh, and revocation are ordinary authorized object
writes of kind `definition_consumer_binding`. Foreign owners cannot
mutate another principal's declarations. A digest mismatch is `stale`,
not a silent repair.

## Completeness

Every report carries one of:

- `complete` — every visible registered declaration in scope was readable
  and digest-fresh
- `partial` — the visible set exceeded the documented bound
- `stale` — at least one matched declaration failed its digest check
- `unavailable` — registration storage or authorization could not be
  evaluated

Zero visible dependents is not proof of zero impact. Hidden consumer
names, paths, counts, and locators stay undisclosed. The report does not
authorize publication.

See [ADR 0067](decisions/0067-definition-consumer-impact.md) and
Discussion [863](https://github.com/Sannrox/sekai-chisei/discussions/863).
