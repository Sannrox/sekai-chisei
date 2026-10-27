# ADR 0134: Federated queries return only suppressed aggregates

- Status: accepted
- Date: 2026-10-26
- Owners: @Sannrox
- Issue: #1464
- Related: [ADR 0099](0099-shared-identity-and-tenancy.md), [ADR 0130](0130-governed-export.md), #878, #1434, #1435

## Context

Shared spaces (#1434) let tenants share objects. Many partners want only
combined statistics across tenants, such as totals, counts and averages, and
must not see each other's records. The plane already evaluates object-set
aggregations under policy pushdown (#878), but only inside the caller's own
tenant, under the caller's own read rights. A requester has no read rights in
another tenant, and should not get any.

## Decision

1. **An agreement per tenant.** A participating tenant's administrator
   publishes a federation allowance:
   - the object type;
   - the properties that may group results (*dimensions*) and those that
     may be measured (*measures*);
   - the allowed functions;
   - a minimum group size `k`;
   - optionally, noise on measures;
   - the requesting tenants or spaces it accepts.

   The allowance is off by default, versioned and audited like a grant. Its
   digest pins what a query ran under.
2. **Decomposable functions only.** The allowed functions are `count`, `sum`
   and `avg`. An average is carried as sum and count. `min`, `max`,
   percentiles and distinct values are refused, since each can reveal a single
   record's value.
3. **Evaluated inside each tenant.** `FederatedAggregate` names the
   participating tenants, a type, dimensions, measures and filters, which may
   use only dimensions. In each tenant, the plane evaluates the aggregation
   under that tenant's policy, as a federation principal bound to the
   allowance. It never uses the requester's identity there.
4. **Suppressed before it leaves.** Each tenant drops every group smaller
   than `k` before returning partials. The combined result drops every group
   smaller than the largest `k` among the tenants that contributed. A
   suppressed group is counted, not described.
5. **Only group keys and numbers leave.** A partial carries dimension values,
   counts and sums. It never carries object ids, rows or non-dimension values.
   Dimension values do leave the tenant. That is the point of a dimension, and
   why a tenant must approve each one.
6. **Exclusions are explicit.** A tenant whose allowance does not cover the
   query (type, dimension, measure, function or requester) contributes
   nothing. It is reported as excluded, with a reason code and no details of
   its allowance.
7. **Optional noise.** A tenant may add bounded Laplace noise to its partial
   sums and counts, with a scale it chooses. The scale and the fact that noise
   was added are returned with the result. This is noise, not a differential
   privacy guarantee: the plane keeps no privacy budget (see Consequences).
8. **Audited everywhere.** Every query writes a receipt in the requesting
   tenant and in every participating tenant. Each receipt records:
   - the query digest and the allowance digest;
   - the groups returned and the groups suppressed;
   - any exclusion.

   The receipts are written before any partial leaves the tenant and closed
   afterwards, as export receipts are (ADR 0130).
9. **One plane.** Federation runs across tenants of one plane. Federation
   across planes is a separate decision.

## Alternatives considered

- **Share the objects in a space and aggregate there.** Rejected: the
  requester would see records.
- **Return raw partials and suppress at the requester.** Rejected: small
  groups would have left the tenant before suppression.
- **Full differential privacy with a per-requester budget.** Deferred. It is
  the stronger guarantee, but it needs budget accounting across queries and
  tenants, and agreed epsilons. Noise plus `k` is the first step and does not
  preclude it.
- **Allow `min` and `max` with `k`.** Rejected: an extreme value is a single
  record's value, whatever the group size.

## Consequences

- **Differencing is the residual risk.** Two queries whose groups differ by
  one record reveal that record's measure. Mitigations:
  - filters use only approved dimensions;
  - `k` applies to every group;
  - noise, where enabled.

  A tenant that needs a formal guarantee should not publish measures until a
  privacy budget exists. Each tenant's receipts let its administrator spot
  repeated narrowing queries. A rate limit per requester and allowance is the
  first follow-up.
- Dimension values leave tenants. An allowance must not name identifying
  properties as dimensions; the console warns on high-cardinality dimensions.
- The aggregation path from #878 gains a federation principal and a
  suppression step. Policy pushdown stays the tenant's own.

## Validation

When implemented, tests show:
- a count and a sum across two tenants returning correct totals, with no row
  or id in the response;
- a group below `k` suppressed, both per tenant and combined;
- a tenant without an allowance for the type excluded and reported as
  excluded;
- `min` and `max` refused;
- receipts written in every participating tenant;
- noise parameters returned when enabled.
