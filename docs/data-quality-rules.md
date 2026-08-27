# Governed data-quality rules

Issue: [#681](https://github.com/Sannrox/sekai-chisei/issues/681)  
Decision: [ADR 0045](decisions/0045-governed-data-quality-rules.md)

A versioned quality rule is not a live scan. Evaluation binds a
`chisei.data-quality-rule/v1` digest to a typed dataset revision and retains a
`chisei.data-quality-result/v1` receipt. Closed states stay distinct. Missing,
invalid, unknown, cancelled, and unavailable results never become pass.

```text
sekaictl admin quality publish --namespace quality --rule-id orders-pin \
  --dataset-id orders --evaluator digest_pin --expected-digest sha256:...
sekaictl admin quality evaluate --namespace quality --rule-id orders-pin
sekaictl admin quality show --namespace quality --rule-id orders-pin
sekaictl admin quality cancel --result-id sha256:...
sekaictl admin quality restart --result-id sha256:...
```

Built-in evaluators are `digest_pin`, `completeness`, and `row_count_bound`.
Replay of a closed identity returns the prior receipt. Restart completes a
cancelled run and keeps the cancelled receipt digest. SQLite is the reference
store. PostgreSQL stays unavailable.
