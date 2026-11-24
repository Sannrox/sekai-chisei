# Execution telemetry

`ChiseiService.GetExecutionTelemetry` returns bounded aggregates over operation
receipts, for reading what happened before proposing a change to routing,
prompts, tools, or policy. Decision: [ADR 0156](decisions/0156-improvement-reads-execution-telemetry-from-the-plane.md).

The RPC is `experimental`: it is rejected unless `SEKAI_EXPERIMENTAL_RPCS=1` or
the `experimental-rpcs` Cargo feature is set.

## Request

| Field | Meaning |
| --- | --- |
| `namespaces` | 1 to 16 namespaces |
| `since_ms`, `until_ms` | half-open window, at most 366 days |
| `group_by` | `task_class`, `model`, `prompt_variant`, `tool`, `evaluator`, or `outcome_class` |

## Response

- `namespaces`: the readable namespaces aggregated.
- `withheld_namespaces`: requested namespaces the caller cannot read. They add
  nothing, not even a count.
- `withheld_receipts`: receipts in readable namespaces with a marking the
  caller is not cleared for. Counted, never aggregated.
- `receipts`, `unrecorded_receipts`: receipts aggregated, and those with no
  value for `group_by`.
- `groups`: per key, receipts, model calls, priced calls, spend in micros,
  input and output tokens, latency p50, p90, and p99 (nearest rank), receipts
  per outcome class, and verifications with passes. `unrecorded` holds
  receipts without the dimension; `other` holds values that are not bounded
  identifiers.
- `gaps`: facts the window could not supply (`no_records_in_window` or
  `not_recorded`), never reported as zero.
- `record_kinds`, `contract_version`, `digest`: what the result was computed
  from, and a `sha256:` digest a learning change can bind as evidence. The same
  closed window returns the same digest.

A window over 366 days, or over the receipt scan cap, fails with
`RESOURCE_EXHAUSTED` and a "narrow the window" message.

## Recording the dimensions

Task class, model, cost, tokens, latency, and outcome come from receipts as
recorded today. The other dimensions read event attributes:

| Dimension | Event | Attribute |
| --- | --- | --- |
| `prompt_variant` | route selected or model called | `prompt_variant` |
| `tool` | action performed | `tool` |
| `evaluator` | verification recorded | `evaluator` |
