# ADR 0037: Project typed events with durable stream checkpoints

- Status: accepted
- Date: 2026-08-26
- Owners: @Sannrox
- Discussion: https://github.com/Sannrox/sekai-chisei/discussions/767
- Issue: https://github.com/Sannrox/sekai-chisei/issues/684
- Supersedes: none
- Superseded by: none
- Related: [ADR 0023](0023-generation-fenced-source-change-feeds.md),
  [ADR 0036](0036-open-table-projections.md),
  Discussion [746](https://github.com/Sannrox/sekai-chisei/discussions/746)

## Context

#668 accepted `sekai.governed-transform-execution/v1`. Its `stream_projection`
class is a typed event projection with durable source identity and a
checkpoint. #672 already owns generation-fenced ordered feeds. The plane must
not become a broker consumer.

## Decision

A registered `sekai.event-stream-projection/v1` binding pins namespace, owner,
source identity, schema revision, and type digest. Batches bind generation,
feed epoch, contiguous offsets, and a content digest. The checkpoint advances
only after a complete authorized batch.

Exact replay is idempotent and does not move the checkpoint twice. Checkpoint
advancement is compare-and-swap on the prior generation, epoch, offset, and
digest. Re-registering the same stream id with a new definition pin resets the
checkpoint. A gap, late offset, malformed event, hidden-field disclosure,
foreign owner, or unsupported revision is a typed non-success and leaves the
checkpoint unmoved. Hidden fields are omitted from the authorized projection.

SQLite is the reference store. PostgreSQL stays unavailable.

## Alternatives considered

Broker consumption was rejected because credentials and remote failure would
become authority. Folding this into Evaluation or ActionInstance was rejected
because those families are gates and effects. Advancing a checkpoint on a
partial or unauthorized batch was rejected because it manufactures success.

## Consequences

Operators register a stream, project ordered batches, and inspect the
checkpoint. Follow-up work added subscriptions in [ADR 0048](0048-governed-event-subscriptions.md).

## Validation

Deterministic fixtures cover accepted projection, exact replay, gap, late,
malformed, hidden-field omission, foreign ownership, and unsupported revision.
