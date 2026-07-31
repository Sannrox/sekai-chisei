# Evaluation-plan operator CLI

`sekaictl admin evaluation plan` is the operator surface for authoring,
publishing, inspecting, and dry-running situation-specific evaluation plans.
It uses the existing Chisei plan, manifest, and deterministic-execution APIs;
it does not introduce a generic evaluator or workflow language.

The authority boundaries are explicit:

1. `validate` reads and canonicalizes a local document. By default it also
   performs authorized, read-only checks of the exact evaluator definitions
   and governed invariant versions. `--offline` limits the command to
   structural validation.
2. `apply` publishes one immutable plan version. An identical replay is
   idempotent. Reusing its namespace, plan ID, and version for different
   canonical content is rejected.
3. `resolve` creates an exact content-bound manifest. It does not run an
   evaluator, collect evidence, grant an action, or make a gate decision.
4. `execute` accepts only an already resolved manifest digest and requires
   `--yes`. It cannot implicitly resolve a plan.

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
- exact content-addressed evaluator and invariant references rather than
  aliases;
- evaluator namespace and current availability;
- closed evaluator parameter schemas and supported input schemas; and
- invariant status, profile-wide applicability, verification contract, and
  typed evaluator compatibility.

Use `--offline` when the server is unavailable. Offline validation still
computes the exact plan version ID, content digest, parameter digests, and
coverage, but publication remains the authoritative check for live reference
visibility and evidence-classification closure.

Publish and inspect:

```bash
sekaictl admin evaluation plan apply \
  tests/fixtures/evaluation/plan-v1.json \
  --target ./data/sekai.sock

sekaictl admin evaluation plan list \
  --namespace acme \
  --plan-id software-release \
  --target ./data/sekai.sock

sekaictl admin evaluation plan inspect \
  evaluation-plan:<64-lowercase-hex> \
  --target ./data/sekai.sock
```

`validate`, `apply`, and `inspect` show canonical plan and parameter digests,
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

## Stable automation and failures

Add `--json` to any command for
`sekaictl.evaluation-plan-output/v1`. Scripts should select fields by name and
must still inspect the process exit status.

| Exit | Meaning |
| ---: | --- |
| `0` | validation, storage, read, resolved manifest, or allow succeeded |
| `2` | local or server validation/conflict failure |
| `3` | resource absent or not authorized; intentionally indistinguishable |
| `4` | resolution or execution is unknown |
| `5` | service, evaluator, resolution, or execution is unavailable |
| `6` | client/server evaluation-plan contract mismatch |
| `7` | deterministic gate denied |

An older server returns exit `6` when it does not implement the additive plan
RPCs. Existing commands and older clients are unchanged because this CLI only
adds the `admin evaluation plan` branch.
