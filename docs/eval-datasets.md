# Eval datasets

Versioned eval datasets (#1673) give evaluations a case set large enough to
compare agent, model and tool versions, built the same way every time.

A dataset is generated, not stored. A checked-in definition
(`chisei.eval-dataset-definition/v1`, under
`tests/fixtures/evaluation/datasets/`) names a synthetic tenant (generator,
fixture namespace, seed and size preset, see synthetic tenants in
`src/sekai/synthetic.rs`) and case templates over its objects:

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
