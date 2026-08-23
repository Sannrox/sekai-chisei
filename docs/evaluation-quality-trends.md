# Evaluation quality trends

`sekaictl report quality` projects model and agent quality evidence from
authorized canonical evaluation receipts. It is a read-only operator report,
not a second evaluation store or a replacement for the fixed gate reducer.

## Query a quality window

Select one namespace and a half-open window:

```sh
sekaictl report quality \
  --namespace acme \
  --since-ms 1783900800000 \
  --until-ms 1784505600000 \
  --json \
  --output reports/acme-quality.json
```

The command reads the backend selected by `DB_PATH` or
`SEKAI_DB_BACKEND=postgres`. With `SEKAI_CREDENTIAL`, the optional
`--principal` or `SEKAI_PRINCIPAL` must match the authenticated principal.
Without a credential, only the trusted local bootstrap principal is available.
Namespace authorization is checked before receipts are listed.

The window cannot exceed 366 days. More than 4,096 receipts fails the query
instead of returning a partial dashboard. Open receipts remain harvestable
only under the receipt store's 24-hour open-operation lookback bound; abandoned
older opens do not reappear in every later window.

Baseline selection uses a separate bounded lookback covering up to 366 days
before `since_ms`. More than 4,096 receipts in that lookback also fails closed.
Baseline-only receipts are authorized and reconstructed by the same path but
do not enter the selected-window series or execution totals.

## Interpret totals

`chisei.evaluation-quality-trend/v1` records both the scanned receipt
denominator and the evaluation subset:

```text
receipts_scanned
  = ignored_non_evaluation_receipts + evaluation_receipts

evaluation_receipts
  = valid_executions + missing_dependencies + invalid_executions

valid_executions
  = allow + deny + unknown + unavailable + cancelled + running
```

`baseline_history_receipts` is reported separately with valid, missing-
dependency, and invalid counts. It is not added to `evaluation_receipts`.

Missing manifests or execution indexes stay `missing_dependencies`. A receipt
whose bindings, step evidence, fixed reduction, cancellation state, or
completeness cannot be reproduced stays `invalid_executions`. Neither state is
omitted or counted as pass. Running work, cancellation, and incomplete
stochastic populations remain explicit; `partial_executions` is a
cross-cutting count and is not another terminal verdict.

Each series binds the exact plan, node, evaluator definition, implementation,
provider, model, and initiating agent. Each point binds the exact manifest,
subject-content revision, evidence-digest set, population, gate, and source
operation. Subject and evidence identities are hidden; evaluator output,
prompts, evidence payloads, and raw provider responses are never projected.

## Baselines, regression, and variance

Points are ordered by evaluation time and operation ID. A baseline is the most
recent earlier closed point in the same exact series with the same canonical
evaluator-input digest, subject content, direct-evidence digest set, and
dependency-result digest set. Stochastic points must also use the same trial
count and aggregation rule.

- `missing` means no earlier closed point exists.
- `incomparable` means earlier points exist but their immutable inputs or
  population contract differ.
- `unavailable` means the current point is running, cancelled, or low-sample.
- `compared` names the exact baseline operation and integer deltas.

If the bounded baseline history contains a missing dependency or invalid
execution that cannot be assigned safely to a series, a point without another
exact comparison reports `unavailable` rather than claiming no baseline.

For complete stochastic populations, lower mean or pass rate, higher variance,
or a transition away from pass/allow is a regression. The inverse is an
improvement. Mixed directions remain `unavailable`; the report does not invent
a scalar weighting. Deterministic comparisons use only closed step and gate
states. A partial population is always `low_sample` and never becomes pass.

The `semantic_digest` covers the window, reconciled totals, series keys, points,
and baseline results. Repeating a query over the same authorized receipt set
returns the same digest.

## Freshness, recovery, and retention

Freshness comes from receipt start/completion times and the manifest's exact
evaluation time. The report does not replace those timestamps with query time.

Execution replay, restart recovery, and durable cancellation remain owned by
`ExecuteEvaluationManifest` and `CancelEvaluationExecution`. The report only
reconstructs their current canonical receipts. A restarted execution can add
the missing immutable step and terminal events; a later query then projects
that updated receipt without rewriting prior events.

Backups and restores must keep evaluation receipts, execution indexes,
manifests, plans, definitions, governed facts, waivers, admitted evidence,
grants, and audit history together. A missing dependency is reported rather
than treated as zero quality. Retention that removes a required receipt or
manifest removes that point from future windows and must be governed by the
existing receipt dependency rules.

Rollback stops using the quality command or deploys a prior binary. It does not
edit receipts, manifests, baselines, or evaluator evidence because the feature
adds no table or mutable analytics state.
