# Event-stream projections

Project typed events with durable source identity, checkpoints, replay bounds,
provenance, and authorization. See
[ADR 0037](decisions/0037-event-stream-projections.md).

## Contract

`sekai.event-stream-projection/v1` is the `stream_projection` class of
`sekai.governed-transform-execution/v1`. The plane does not open brokers or
store source credentials.

## Operator workflow

```text
sekaictl admin streams register --binding ./binding.json --actor analyst
sekaictl admin streams project --batch ./batch.json --actor analyst
sekaictl admin streams checkpoint --stream-id github:ops
```

The first batch must start at offset 1. Later batches must be contiguous.
Exact replay of the last committed digest returns `replayed` and does not move
the checkpoint. Re-registering the same stream id with a new source, type
digest, schema, or columns resets the checkpoint so the next batch starts at
offset 1. Checkpoint advancement is compare-and-swap on the prior generation,
epoch, offset, and digest.

## Failure

| Condition | Result |
| --- | --- |
| Unknown stream or foreign owner | `event stream projection is not admitted` |
| Missing offset or generation/epoch mismatch | `event stream batch has a gap` |
| Offset already committed with a different digest | `event stream batch is late` |
| Bad offsets, types, or digest | `event stream batch is malformed` |
| Unknown schema revision | `event stream revision is unsupported` |

Hidden fields are omitted. Partial output is discarded. SQLite stores
bindings and checkpoints; PostgreSQL stays unavailable.
