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
