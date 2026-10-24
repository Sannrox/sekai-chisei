# Authorized consumer impact

`ReportDefinitionConsumerImpact` joins `CompareDefinitionRevisions` to
explicit `sekai.definition-consumer-binding/v1` objects. Both RPCs are
classified `experimental` and are rejected unless `SEKAI_EXPERIMENTAL_RPCS=1`
or the `experimental-rpcs` Cargo feature is enabled. See
[rpc-maturity.md](rpc-maturity.md). Bindings may name
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
names, paths, counts, and locators of advisory bindings stay undisclosed.
An advisory report does not authorize or block publication.

## Blocking bindings

A consumer may set the property `blocking` to `true` on its binding (the
declaration digest then covers the flag). A blocking binding:

- is disclosed to producers: impact reports include it whatever the caller
  can see, marked `blocking`;
- blocks publishing: `MergeDefinitionProposal` fails with
  `FAILED_PRECONDITION` (`definition_publish_blocked`) when the revision
  would remove or change a member or property it depends on, naming each
  blocking binding;
- does not block a proposal created with `major_revision: true` once that
  proposal is approved and merged; the flag is part of the approved
  proposal digest.

A blocking binding with a stale digest does not block.

## Violation notifications

A freshness or quality violation writes one durable delivery per
`(recipient, event)` at commit for digest-fresh bindings of that dataset.
`ListConsumerViolationNotifications` is caller-scoped and paged.
`AcknowledgeConsumerViolationNotification` acknowledges the caller's row.
Evidence is stored in full and omitted at read when the caller cannot read
the dataset. Email and webhooks stay out of the core.

See [ADR 0067](decisions/0067-definition-consumer-impact.md) and
Discussion [863](https://github.com/Sannrox/sekai-chisei/discussions/863).
