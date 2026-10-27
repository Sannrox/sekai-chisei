# Ontology changelog

`GetOntologyChangelog` lists what changed in a reader's namespaces over a
window of at most 31 days, oldest first. It is experimental: it needs
`SEKAI_EXPERIMENTAL_RPCS=1` or the `experimental-rpcs` Cargo feature (see
[rpc-maturity.md](rpc-maturity.md)).

A weekly team digest is a call with a seven-day window and the team as
`reader`. Only a credential admin may name a reader other than themselves,
and the digest is then authorized as that reader alone, never with the
admin's own access. With the enterprise extension installed a reader's access
depends on their own tenant context, so a digest for another reader is
refused with `FAILED_PRECONDITION` for now; readers can request their own.

## Entries

| Kind | Source | Fields |
| --- | --- | --- |
| `definition_revision` | each published definition revision (a merged proposal) | plain-language summary of the diff, compatibility class, proposal author, approvers, publisher, receipt, and the registered consumers the change affects |
| `policy_activation` | the namespace's current object-security activation, when it falls in the window | the policy revision per kind whose object type the reader may read, and who activated it |

The summary has one line per added, removed or changed member, naming added,
removed and changed properties. Affected consumers come from
`sekai.definition-consumer-binding/v1` registrations, as in
`ReportDefinitionConsumerImpact`: the plane does not infer undeclared
consumers.

## Visibility

- With no `namespaces`, the changelog covers every namespace the reader holds
  a role in.
- A namespace the reader cannot read contributes no entry.
- Diffs leave out members the reader cannot read, the compatibility class
  comes from the readable members only, and a revision with no readable
  change leaves no entry.
- Only consumer bindings the reader can see are listed.

## Bounds and gaps

At most 50 namespaces, and per namespace 200 published revisions in the
window and 5,000 history rows scanned to reach it; more fail with
`RESOURCE_EXHAUSTED` or `INVALID_ARGUMENT`. Entries are derived
on read; nothing new is stored.

Not yet covered: delivering the digest as an event for notification
channels, earlier policy activations (only the current one is retained), and
migration bundles, data-contract changes and health-score changes as entry
sources.
