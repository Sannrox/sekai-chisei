# ADR 0156: Improvement reads execution telemetry from the plane

- Status: accepted
- Date: 2026-11-24
- Owners: @Sannrox
- Issue: https://github.com/Sannrox/sekai-chisei/issues/2640 (#2640)
- Supersedes: none
- Superseded by: none
- Related: [ADR 0043](0043-reversible-learning-changes.md)

## Context

Improving routing, prompts, tools, and policy needs to read what happened:
which model and prompt variant a task class used, its cost, latency, outcome,
and verification results. Traces go to an external collector, outside the
plane's markings and namespace authorization. Metrics carry only closed labels.
Per-operation aggregation (`src/operation_statistics.rs`) feeds only the
console. A learning candidate binds an evidence digest, but no governed read
produced that evidence.

## Decision

- **One read.** `ChiseiService.GetExecutionTelemetry` (experimental) returns
  bounded aggregates over durable operation receipts for 1 to 16 namespaces and
  a half-open window. It adds no store and copies no traces. Per-operation
  detail stays behind `GetOperationReceipt` and the report reads.
- **Dimensions.** The result is grouped by one closed dimension:
  - `task_class`: the receipt's operation class;
  - `model`: each model call is attributed to its own model, so a receipt
    that used two models counts in both groups, each with its own calls;
  - `prompt_variant`: the `prompt_variant` attribute on route or model-call
    events;
  - `tool`: the `tool` attribute on action events;
  - `evaluator`: the `evaluator` attribute on verification events;
  - `outcome_class`: the outcome classes `GetOperationStatistics` already
    uses.

  A receipt with several values counts once in each of its groups. A receipt
  with none goes to `unrecorded`. A value that is not a bounded identifier
  (at most 128 bytes) goes to `other`, so free text never becomes a key.
- **Facts.** Per group: receipts, model calls, priced calls, spend in micros,
  input and output tokens, latency samples with nearest-rank p50, p90, and p99,
  receipts per outcome class, and verifications with their pass count. Nothing
  carrying prompts, inputs, outputs, or provider responses is returned or
  grouped by.
- **Access.** Each namespace needs namespace read. A namespace the caller
  cannot read, or one that does not exist, is listed in
  `withheld_namespaces` and contributes nothing. Its record count is not
  returned, because a count would disclose another tenant's activity. Inside a
  readable namespace, a receipt with a marking the caller is not cleared for
  is left out and only counted in `withheld_receipts`, using the same
  clearance check as `GetOperationReceipt`. A failed clearance lookup
  withholds the receipt.
- **Bounds.** The window is at most 366 days, and the scan is capped at the
  `GetOperationStatistics` receipt cap. Withheld receipts count toward that
  cap. Past either cap the call fails with `RESOURCE_EXHAUSTED` and a
  "narrow the window" message; it never truncates.
- **Gaps.** A fact the window cannot supply is reported in `gaps`, never
  counted as zero: no receipts, no model calls, no latency or token usage
  recorded, no verifications, or a dimension no receipt records. Operation
  receipts have no retention purge today. A later purge must report the purged
  range as a gap.
- **Evidence.** The result names `record_kinds` (`operation_receipt`), the
  window, and the contract `chisei.execution-telemetry/v1`. Its `digest` is
  `sha256:` over the canonical JSON of every other field, so a learning
  candidate can bind it. Re-reading a closed window returns the same digest.

## Consequences

- Learning candidates, allocation, operators, and agents read one governed
  source. Aggregates are only as complete as the receipts; prompt variant,
  tool, and evaluator are mostly unrecorded today and show as gaps until
  producers record them.
- Gateway call records are not read yet. They become a second record kind
  when a consumer needs them, and `record_kinds` names it.
- Proto: the new RPC and the `GetExecutionTelemetryRequest`,
  `GetExecutionTelemetryResponse`, `ExecutionTelemetryGroup`, and
  `ExecutionTelemetryGap` messages. No migration on SQLite or PostgreSQL; the
  read uses the existing receipt window scan. Rollback removes the RPC only.

## Rejected

- **Ingesting traces back into the plane.** A second store with weaker access
  rules.
- **Reading the collector directly.** Outside markings and authorization.
- **One read per record kind.** Pushes joins onto every consumer.
- **Counting records in unreadable namespaces.** Discloses activity volume.
