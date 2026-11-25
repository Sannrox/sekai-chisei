# ADR 0164: Reads withhold what a reader's egress may not receive

- Status: accepted
- Date: 2026-11-25
- Owners: @Sannrox
- Issue: https://github.com/Sannrox/sekai-chisei/issues/2699 (#2699)
- Supersedes: none
- Superseded by: none
- Related: [ADR 0152](0152-gateway-is-the-model-egress-layer.md), [ADR 0038](0038-property-level-reads.md), [ADR 0032](0032-hierarchical-classifications.md)

## Context

ADR 0152 decision 7 puts disclosure where data leaves Sekai: a read checks
each field's data class against the reading principal's allowed egress, which
the gateway publishes. It leaves open what a field's data class is, how
egress is computed from the published policy, what a deployment without a
gateway does, and how a reader learns that a value was withheld. The
maintainer accepted the drafted answers on #2699.

## Decision

1. **Data class.** A property's schema `classification` (`public`,
   `internal`, `sensitive`; empty is `public`) is its data class. It is
   compared with the gateway's `egress[].data_classes` labels after the
   gateway's normalization. A class may reach a route when the route's
   provider lists it. `public` gets no special case.
2. **Allowed egress.** For each configured gateway, the gateway principals
   whose `sekai_principal` (default `name`) equals the reader contribute their
   routes' providers. The reader receives the classes every one of those
   providers releases. A delegated request takes the strictest answer over its
   principals and actor.
3. **Unknown egress.** A reader that maps to no gateway principal, or whose
   mapping reaches no route, receives only the classes every provider in every
   configured policy releases. A gateway whose policy is unread, or whose last
   read failed, releases nothing, so the answer fails closed.
4. **No gateway configured.** With `CHISEI_GATEWAY_LOGS` unset there are no
   routes to compute against, and reads behave as before this decision.
5. **Withheld, not silently omitted.** A withheld value is absent from the
   returned object. `GetObject`, `EvaluateObjectSet`, `Search`,
   `ExpandNeighborhood` and `GetLineage` list the withheld properties of the
   returned kinds as `withheld_properties` (`kind`, `property`, and the
   reason `egress_not_allowed` or `egress_unknown`; experimental, additive).
   Properties a property grant hides are never listed (ADR 0038).
6. **Matching.** A withheld property takes no part in a query: a filter,
   sort, group or facet naming it is refused before the query, and Search
   neither matches nor highlights it.
7. **Policy source.** Every process that serves Sekai polls each configured
   gateway's `GET /_chisei/policy` with that gateway's `log_reader` key and
   keeps the latest valid view in memory. The view is derived state: each
   instance polls on its own and starts with every policy unread. The Sekai
   plane accepts `CHISEI_GATEWAY_LOGS` for this alone; only the combined
   server reads the logs.

## Alternatives considered

- **Treat every principal as unknown egress when no gateway is configured.**
  The literal reading of ADR 0152. Every deployment without a gateway would
  lose `internal` and `sensitive` values on every read, with no route to
  compute against.
- **Keep the last good policy after a failed read.** Avoids withholding
  during a gateway outage, but serves values under a policy the operator may
  have tightened since.
- **Report withheld properties per object.** Reveals which objects hold a
  value. Per kind reveals only the schema the reader may already read.
- **Withhold only on the RPCs MCP dispatches to.** Leaves the same values
  reachable through other native reads. Withholding happens in the shared
  response projection, so every read that projects through it withholds, and
  the five RPCs above also report it.

## Consequences

- Once a gateway is configured, principals with broad egress, client-login
  passthrough, or no gateway mapping see fewer property values over MCP and
  native reads. Operators map Sekai principals to gateway principals with
  `sekai_principal` in the gateway policy.
- A gateway outage withholds every class its policy would release from
  everyone until the next good read. Each gateway reports this as the gRPC
  health service `chisei.gateway_policy.<name>`.
- Reads other than the five above withhold the same values without listing
  them. Listing them there, and in exports and dataset reads, is follow-up
  work.

## Validation

- Over MCP, a `sensitive` property is withheld from a reader whose route may
  not receive it (`egress_not_allowed`) and from an unmapped reader
  (`egress_unknown`), and returned to a reader whose only route is local.
- A filter on a withheld public property is refused, and Search does not
  match a withheld value that a local reader finds.
- Unit tests cover no gateway, mapping by `sekai_principal`, the strictest
  delegated answer, an unread policy, and a route without an egress rule.
