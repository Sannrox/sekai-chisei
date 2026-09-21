# Evaluation-plan operator CLI

`sekaictl admin evaluation plan` is the operator surface for authoring,
publishing, running, and comparing situation-specific evaluation plans.
Its commands call `PutEvaluationPlan`, `ResolveEvaluationPlan`,
`ExecuteEvaluationManifest`, and `GetOperationReceipt`, all classified
`stable` in the default build. See [rpc-maturity.md](rpc-maturity.md).
It uses the existing Chisei plan, manifest, and bounded-execution APIs;
it does not introduce a generic evaluator or workflow language.

Three neighboring RPCs stay `experimental` and need the **server** to be
started with `SEKAI_EXPERIMENTAL_RPCS=1` (or built with the `experimental-rpcs`
Cargo feature; setting the env only in the `sekaictl` client process does not
enable them): `GetGovernedFactVersion`, which live `validate` reads without
`--offline` (`apply` performs the authoritative check without it);
`PutEvaluatorDefinition`, which is operator deployment work rather than a CLI
verb; and `CancelEvaluationExecution`, which has no CLI verb.

The authority boundaries are explicit:

1. `validate` reads and canonicalizes a local document. By default it also
   performs authorized, read-only checks of exact governed invariant versions.
   `apply` performs the authoritative evaluator checks. `--offline` limits the
   command to structural validation.
2. `apply` publishes one immutable plan version. An identical replay is
   idempotent. Reusing its namespace, plan ID, and version for different
   canonical content is rejected.
3. `resolve` creates an exact content-bound manifest. It does not run an
   evaluator, collect evidence, grant an action, or make a gate decision.
4. `execute` accepts only an already resolved manifest digest and requires
   `--yes`. It cannot implicitly resolve a plan.
5. `compare` only reads the receipts of two finished executions. It never
   executes, resolves, or waits.

## Author a plan

Start with the [complete plan fixture](../tests/fixtures/evaluation/plan-v1.json).
Replace its placeholder exact evaluator-definition and governed-invariant IDs
with versions already registered in the target namespace. The preferred
authoring form uses a JSON object in `parameters`; the CLI canonicalizes it to
the protocol's `parameters_json` field.

Each plan is situation-specific. Its subject profiles, exact evaluator
versions, input schemas, parameters, dependency graph, invariant coverage, and
required/advisory classifications should describe the concrete decision being
evaluated. V1 accepts only the fixed fail-closed reducer.

Validate without publishing:

```bash
sekaictl admin evaluation plan validate \
  tests/fixtures/evaluation/plan-v1.json \
  --target ./data/sekai.sock
```

Live validation checks:

- graph bounds, unique nodes and bindings, dependencies, cycles, and required
  invariant coverage;
- exact content-addressed invariant references rather than aliases; and
- invariant status, profile-wide applicability, and verification contract.

Use `--offline` when the server is unavailable. Offline validation still
computes the exact plan version ID, content digest, parameter digests, and
coverage, but publication remains the authoritative check for live reference
visibility and evidence-classification closure.

Publish:

```bash
sekaictl admin evaluation plan apply \
  tests/fixtures/evaluation/plan-v1.json \
  --target ./data/sekai.sock

```

`validate` and `apply` show canonical plan and parameter digests,
exact evaluator bindings, and invariant coverage. Human output omits raw
parameters and source references.

## Resolve without executing

Copy the [resolution fixture](../tests/fixtures/evaluation/resolution-v1.json),
then set the exact plan ID, subject identity and digest, evidence object IDs,
and an evaluation time that is not in the future:

```bash
sekaictl admin evaluation plan resolve ./resolution.json \
  --target ./data/sekai.sock
```

A successful response shows the manifest and plan digests, evaluator bindings,
invariant coverage, waiver state, and whether evidence was admitted and fresh.
Human output redacts the subject identity plus evidence and waiver identifiers.
It never prints evidence payloads, evaluator parameters, prompts, credentials,
or source references. Authorized JSON output includes exact identifiers and
metadata, but no evidence or evaluator-result content:

```bash
sekaictl admin evaluation plan resolve ./resolution.json \
  --target ./data/sekai.sock \
  --json
```

Resolution exit status is `0` only for `resolved`. It is `4` for `unknown` and
`5` for `unavailable`, so automation cannot mistake uncertainty for success.

## Explicit execution

Execution is separate and requires confirmation:

```bash
sekaictl admin evaluation plan execute \
  acme \
  sha256:<64-lowercase-hex-manifest-digest> \
  --yes \
  --max-duration-ms 30000 \
  --target ./data/sekai.sock
```

The output contains receipt digests, bounded reason codes, invariant coverage,
and the fixed gate decision. It contains no evaluator output or evidence
payload. An `allow` exits `0`; `deny` exits `7`; `unknown` exits `4`; and
unavailable, cancelled, or incomplete execution exits `5`.

## Compare two finished executions

Comparison is a read-side projection over immutable, receipted runs, not a new
authority. Pin two exact manifest digests of one namespace, execute both, then
diff them:

```bash
sekaictl admin evaluation plan compare \
  acme \
  sha256:<64-lowercase-hex-baseline-manifest-digest> \
  sha256:<64-lowercase-hex-candidate-manifest-digest> \
  --target ./data/sekai.sock
```

Each side is rebuilt from the canonical operation receipt of that manifest
digest through `GetOperationReceipt`; the diff is a pure function of the two
receipts. Nodes are matched by node ID. Only `pass` (and the `allow` gate
verdict) counts as good, so a node or verdict is:

- `improved` when a non-pass became a pass and `regressed` when a pass became
  a non-pass;
- `changed` for any other difference, such as a different non-pass state or
  reason code, without ranking kinds of inconclusive outcome;
- `added` or `removed` when a node exists on one side only; and
- `unchanged` otherwise.

The overall outcome is `regressed` when the gate verdict worsened or a
`required` node regressed or was added without passing, `improved` when
nothing regressed and the gate or a `required` node improved, and `unchanged`
otherwise. Advisory movement, better or worse, is reported and counted but
never decides the outcome, mirroring the fixed reducer. For nodes on both sides the output also names
which receipt digests differ (`input`, `parameters`, `evaluator_definition`,
`implementation`, `evidence`, `dependency_results`, `result`), which is where
to look for why. Evaluator output and evidence payloads are never persisted in
receipts and never appear.

`compare` exits `0` for `unchanged` and `improved`, and `8` for `regressed` so
CI can gate on it. Both digests must be different and exact. An execution that
is still running or was cancelled exits `5`. An execution that does not exist,
belongs to another namespace, or is not visible to the caller exits `3`,
indistinguishable by design. Execution receipts are visible to the principal
that started the execution and to local administrative inspection, exactly as
for `GetOperationReceipt`. `--json` prints
`chisei.evaluation-comparison/v1` under `comparison`.

## Stable automation and failures

Add `--json` to any command for
`sekaictl.evaluation-plan-output/v1`; `compare` reports its outcome in
`status` and its diff under `comparison`. Scripts should select fields by name and
must still inspect the process exit status.

| Exit | Meaning |
| ---: | --- |
| `0` | validation, storage, resolved manifest, or allow succeeded |
| `2` | local or server validation/conflict failure |
| `3` | resource absent or not authorized; intentionally indistinguishable |
| `4` | resolution or execution is unknown |
| `5` | service, evaluator, resolution, or execution is unavailable |
| `6` | client/server evaluation-plan contract mismatch |
| `7` | fixed evaluation gate denied |
| `8` | `compare`: the candidate regressed against the baseline |

An older server returns exit `6` when it does not implement the additive plan
RPCs. Existing commands and older clients are unchanged because this CLI only
adds the `admin evaluation plan` branch.
