# ADR 0144: FederatedAggregate withholds the suppressed-group count from the caller

- Status: accepted
- Date: 2026-11-07
- Owners: @Sannrox
- Discussion: none, resolved in Issue #2027
- Issue: #2027
- Supersedes: [ADR 0134](0134-federated-aggregate-queries.md) for the caller-response suppressed-group count
- Superseded by: none
- Related: [ADR 0130](0130-governed-export.md)

## Context

ADR 0134 §4 counts suppressed groups and returns that count on the
combined result, without describing the groups. `FederatedAggregate`
copied the exact total onto the caller response. A reader who already
knows `k` then uses the count as a small-group oracle: an empty result
with `suppressed_groups = 1` means 1..k-1 matching records, and
`suppressed_groups = 0` means none. Range filters binary-search rare
values. Noise on group measures does not cover this field.

Participant receipts already record the same count for the allowance
owner (ADR 0134 §8). The RPC is experimental.

## Decision

1. **The caller response does not carry a suppressed-group count.** The
   proto field stays (always 0) so the experimental contract does not
   drop a field. Groups, `min_group_size`, contributors, exclusions and
   noise reports are unchanged.
2. **The requester receipt does not carry that count either.** The
   requesting namespace already sees the returned groups; putting the
   exact suppressed total on its receipt would restore the oracle if
   receipts become readable there.
3. **Participant receipts keep the per-namespace count** for the
   allowance owner.

## Alternatives considered

- Noise or bucket the count before it reaches the caller. Rejected: a
  0-versus-1 count with typical scales still distinguishes no matches
  from a small group, and the allowance owner already has the exact
  figure on its receipt.
- Remove the proto field. Deferred: the RPC is experimental and not in a
  tag, but keeping the field at 0 avoids a generated-type break while
  closing the oracle.

## Consequences

Callers no longer learn how many groups `k` dropped. Allowance owners
still see per-namespace suppression on their receipts. Differencing two
queries that differ by one record remains the residual named in ADR
0134.

## Validation

Tests cover: a filter with no matching records and a filter with
fewer-than-`k` matching records return the same `suppressed_groups` on
the response; participant receipts still record the exact per-namespace
count; the requester receipt does not.
