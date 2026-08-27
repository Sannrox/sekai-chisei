# Event-stream projections

Project typed events with durable source identity, checkpoints, replay bounds,
provenance, and authorization. See
[ADR 0037](decisions/0037-event-stream-projections.md) and
[ADR 0048](decisions/0048-governed-event-subscriptions.md).

## Contract

`sekai.event-stream-projection/v1` is the `stream_projection` class of
`sekai.governed-transform-execution/v1`. A consumer cursor is a
`sekai.event-subscription/v1` object. The plane does not open brokers or
store source credentials.

## Operator workflow

```text
sekaictl admin streams register --binding ./binding.json --actor analyst
sekaictl admin streams project --batch ./batch.json --actor analyst
sekaictl admin streams checkpoint --stream-id github:ops
sekaictl admin streams subscribe --binding ./subscription.json --actor analyst
sekaictl admin streams pull --page ./page.json --actor analyst
sekaictl admin streams cursor --namespace ops --subscription-id ops-alerts --actor analyst
sekaictl admin streams revoke --namespace ops --subscription-id ops-alerts --actor analyst
```

The first batch must start at offset 1. Later batches must be contiguous.
Exact replay of the last committed digest returns `replayed` and does not move
the checkpoint. Re-registering the same stream id with a new source, type
digest, schema, or columns resets the checkpoint so the next batch starts at
offset 1. Checkpoint advancement is compare-and-swap on the prior generation,
epoch, offset, and digest.

A subscription is an independent cursor over pages the stream checkpoint has
already admitted. Each accepted event stores a content commitment. Exact replay
of the last page digest returns `replayed`. Re-registering the same pins keeps
the cursor unless the retention window has elapsed; then re-register resets it.
An idle cursor older than the bound retention window cannot disclose a page,
including exact replay. Revocation is durable; the
same identifier cannot be reactivated. Checkpoints that predate event
commitments are cleared so the next project starts at offset 1.

## Failure

| Condition | Result |
| --- | --- |
| Unknown stream or foreign owner | `event stream projection is not admitted` |
| Missing offset or generation/epoch mismatch | `event stream batch has a gap` |
| Offset already committed with a different digest | `event stream batch is late` |
| Bad offsets, types, or digest | `event stream batch is malformed` |
| Unknown schema revision | `event stream revision is unsupported` |
| Unknown, foreign, or revoked subscription | `event subscription is not admitted` |
| Page ahead of the stream checkpoint or cursor | `event subscription page has a gap` |
| Page already committed with a different digest | `event subscription page is late` |
| Idle cursor older than the retention bound | `event subscription retention window elapsed` |

Hidden fields are omitted. Partial output is discarded. SQLite stores
bindings, checkpoints, and subscriptions; PostgreSQL stays unavailable.
