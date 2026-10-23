# Operation correlation

A governed action can carry one caller-chosen operation identity across the
inbound span, the durable receipt, and the object-change event. The identity
is an opaque key. The plane never derives it from request content, so equal
identities do not prove equal inputs.

## Carriers

| Carrier | Name |
| --- | --- |
| gRPC / HTTP header | `x-sekai-operation-id` |
| W3C trace parent | `traceparent` / `tracestate` |
| Span attribute | `sekai.operation_id` |
| Receipt field | `OperationReceipt.operation_id` |
| Object-change field | `ObjectChange.operation_id` and `ObjectChangeEvent.operation_id` |

`SubmitActionInstanceRequest.request_id` is the same identity. When the
header and `request_id` are both set, they must match. When only one is set,
it becomes the bound identity. When both are empty, admission mints
`op-gai-*` and returns it on the instance. Callers that must correlate a
refused RPC should send the header, because generic gRPC error propagation
does not guarantee generated response metadata.

The generated span field `operation` remains an opaque process-local
correlation id. It is not the cross-plane identity and is not derived from
the caller key.

## Object change history

Each object change row stores the operation that produced it. An admitted or
granted Action writes its `operation_id` on every change its object write
records; other writes store an empty value. `ListObjectChanges` returns the
stored value per change, so two changes written in the same instant by
different operations keep distinct identities. Changes are never linked to an
operation by timestamp. Rows written before this field existed keep an empty
value. `ListObjectChanges` has the same semantics and paging on SQLite and
PostgreSQL; it is experimental and needs `SEKAI_EXPERIMENTAL_RPCS=1` or the
`experimental-rpcs` build feature.

### Writer attribution

Each change row also records who wrote it (#1690): `writer_kind`,
`writer_ref`, and `receipt_id`.

| `writer_kind` | `writer_ref` | `receipt_id` |
| --- | --- | --- |
| `source_transaction` | the committed source batch transaction | the same transaction record |
| `transform_run` | `run_id@checkpoint` (streaming apply checkpoint, or the run's last input row) | the transform run |
| `action_instance` | the Action instance | the Action's operation receipt |
| `direct` | empty | empty |
| `unattributed` | empty | empty |

A transform that stamps an output marking records the stamp as a change of
`properties.access_marking`, attributed to the run. Direct object RPC writes
record `direct`. Rows written before the columns existed, by a version
without them during a rolling deploy, or by internal writers that record no
writer read as `unattributed`; the writer is never inferred. The columns are
nullable on both backends (PostgreSQL `0098_object_change_writer`).

## Client propagation

SDK callers set the header through the existing operation context:

- TypeScript / generated clients: `operationId` on the call context
- Python: `operation_id` on the call context
- Rust `sekai-client`: `OPERATION_METADATA` (`x-sekai-operation-id`)

Send a W3C `traceparent` when a parent trace exists. The plane accepts it at
the trusted gRPC boundary and does not forward it to model providers.

## Failure

Whitespace, non-ASCII, or identities longer than 200 characters fail closed.
A mismatched header and `request_id` is `INVALID_ARGUMENT`.
