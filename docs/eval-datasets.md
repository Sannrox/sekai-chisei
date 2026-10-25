# Eval datasets

Versioned eval datasets (#1673) give evaluations a case set large enough to
compare agent, model and tool versions, built the same way every time.

A dataset is generated, not stored. A checked-in definition
(`chisei.eval-dataset-definition/v1`, under
`tests/fixtures/evaluation/datasets/`) names a synthetic tenant (generator,
fixture namespace, seed and size preset, see synthetic tenants in
`crates/sekai-core/src/sekai/synthetic.rs`) and case templates over its objects:

```json
{
  "contract_version": "chisei.eval-dataset-definition/v1",
  "name": "supply-chain-triage",
  "generator": "supply_chain",
  "namespace": "eval-supply-chain",
  "seed": 1673,
  "preset": "load_test",
  "templates": [
    {"id": "shipment-status", "kind": "synthetic_shipment",
     "input_properties": ["tracking", "quantity"], "expected_property": "status",
     "tags": ["shipment", "status"]}
  ]
}
```

Each template yields one case per object of its kind, as the tenant stands
once its synthetic Action history has been applied: the object id, kind,
namespace and the input properties are the input, the expected property is
the expected outcome, and the template's tags are the case's tags. A
template may not use its expected property as input.

- **Versions are immutable.** Generation is deterministic, and the version
  (`v` and 16 hex digits) is derived from the dataset digest, which covers
  the definition, the synthetic plan's digest, the generator version and the
  cases. The same seed gives the same digest and version; a new seed, a
  template edit or a generator change gives a new version. Resolving
  `name@version` regenerates the dataset and answers "not found" for a
  version the definition no longer produces.
- **Fixture tenants only.** Cases name only the synthetic namespace they were
  generated from, so the tools a case exercises act on fixture data.
- **The existing executor runs them.** `EvalDataset::evidence` turns a case
  into evaluation evidence (`chisei.eval-case/v1`) naming the dataset version
  and digest, for the evaluation executor (docs/evaluation-execution.md).
  Its step receipts pin each case; there is no separate eval store.

Datasets built from recorded traces and model-graded rubrics are out of
scope.

## Runs

`ChiseiService.RunEvalDataset` (experimental, #1674) runs every case of one
dataset version through a registered evaluator definition that accepts
`chisei.eval-case/v1`, against a named agent, model and tool version, and is
started by CI or the delivery plane per release. It is rejected unless
`SEKAI_EXPERIMENTAL_RPCS=1` or the `experimental-rpcs` Cargo feature is
enabled. Datasets resolve from the
definitions in `CHISEI_EVAL_DATASETS_DIR`.

- At most `concurrency` cases (1 to 64) run at once, and one start of a run
  at a time: a start holds the run's lease (two minutes, renewed before every
  case), another start meanwhile is refused `ABORTED`, and a crashed start's
  lease lapses for the next.
- Every case reserves `max_case_cost_micros` before it starts and starts only
  while the spent cost, the reservations of cases in flight and its own fit
  `budget_micros`; then the run ends `budget_exhausted` with the unrun cases.
  A stochastic definition must run on the run's model, must have a price in
  `CHISEI_GATEWAY_PRICING`, and must not be able to cost more per case (its
  `max_total_tokens` at the higher token price) than `max_case_cost_micros`,
  all checked before any case runs.
- Before a case is dispatched its cap moves durably into the run's
  uncertain spend, and recording its result moves it back out in the same
  write, both only while the start holds the lease. A start that crashed
  after an evaluator charged therefore leaves that spend counted against the
  budget (`uncertain_micros`), never lost.
- Each case result is durable per (run, case) and written once
  (`chisei_dataset_runs`, `chisei_dataset_run_cases`). Starting the run again
  with the same `run_id` resumes: only cases without a result run, and the
  ledger (tokens and cost per case) and its total cover every start. A
  `run_id` is bound to its first spec, including the evaluator definition and
  its digest; another spec under it is refused.
- Only a pass or fail verdict is a result. A case that failed to run stays
  unrun and the run is `incomplete`, to be resumed. If nothing was
  dispatched (a deterministic evaluator unavailable) its reservation is
  given back; if a model may have charged (a stochastic call that timed out
  or failed) the reservation stays counted, so retries cannot outspend the
  budget. A stochastic definition's provider must also pass the configured
  egress allowlist, checked before any case runs.

## Policy outcomes

A case can pass its task and still break policy. Each case result records
its policy outcome, scored apart from the verdict (#1676,
`chisei.eval-policy-scorer/v1`). The scorer reads the receipts the executor
reports for the case and checks them against what the case principal may
call and read:

| Kind | A receipt shows |
| --- | --- |
| `ungranted_tool_call` | a call to a tool the case principal has no grant for |
| `marking_leak` | an output that carries a value the case principal cannot read |
| `action_outside_approval` | an Action applied with no approval receipt |
| `missing_receipts` | nothing: the case's receipts were not reported |

The scoring fails closed: a case without receipts is never clean, and
neither is a result recorded before scoring existed or by another scorer
version. Only the outcome is stored with the result, never the receipts.
`RunEvalDatasetResponse` reports:

- the scorer version;
- a count for every kind, zero when none was found;
- each violation with its case and receipt id.

An evaluator definition judges a case's evidence. It calls no tool, writes
no output, and applies no Action, so its cases report empty receipts.


## Baseline comparison

`ChiseiService.CompareEvalDatasetRuns` (experimental, #1677) compares a
candidate run with a baseline run of the same dataset version, case by case.
Both runs must have a result for every case. A partial run is refused,
never compared.

- **Significance.** An exact one-sided McNemar test runs on the discordant
  pairs: `regressions` (baseline passed, candidate failed) against
  `improvements`. The p-value is `P(X >= regressions)` for
  `X ~ Binomial(regressions + improvements, 1/2)`. A regression is
  significant when there are more regressions than improvements and the
  p-value is below `alpha` (default 0.05).
- **Policy.** Violation counts are compared kind by kind, and every kind
  whose count rose is listed in `policy_increased`.
- **Gate.** The verdict is `fail` on a significant regression, or on a
  policy increase unless `allow_policy_increase` is set. `reasons` names
  why.

`ExportModelEvaluationEvidence` with `dataset_namespace` set signs the release
evaluation evidence from this comparison. The outcome is the gate's verdict.
The candidate run must run the released model and be bound to its artifact.
`RunEvalDataset` with `artifact_digest` binds a new run once
(`chisei_dataset_run_artifacts`). Binding is an attestation that the run is
that release's evaluation, so it takes the same credential-administration
authority as the export. Only a run whose evaluator runs on the released
model can be bound or exported. A deterministic evaluator judges the
dataset alone, whatever the run's model label says. The evidence's
`eval_suite_id` and `eval_run_id` are derived from the dataset and run ids,
which the ledger record keeps as they are. A run started without one cannot be bound
later, and a bound run cannot be rebound. The comparison is kept in the
export's decision ledger record and returned as `comparison_json`.

`ChiseiService.ListEvalDatasetRunTrend` lists every run of a dataset in a
namespace, oldest first. Each run has its agent, model, tool version, start
time, cases recorded and passed, and policy counts, for trend views.
