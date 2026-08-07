# Lookup-first promotion gate

Issue: [#529](https://github.com/Sannrox/sekai-chisei/issues/529).

The v1 gate is the narrow correctness boundary for promoting a structured
lookup-first contract. It executes an operator-owned, versioned suite against
authorized graph state, requires every `lookup_hit` to equal its structured
golden answer, and records a bounded audit decision. It does not call a model,
apply route policy, or promote a namespace automatically.

The suite contract is
`chisei.lookup-first-promotion-gate/v1`. Every case must use one of the
allow-listed structured capabilities, an object-valued JSON input, and either:

- `expected_path: lookup_hit` plus `expected_answer`; or
- `expected_path: model_path` plus the exact bounded `expected_refusal`.

Free-form natural-language cases and the cheap-model generative arm are
rejected. #527 selected eval-gated promotion as a future control and did not
recommend model-vs-model evidence for this v1 follow-up.

## Run the gate

The checked-in example is
[`promotion-gate-v1.json`](../tests/fixtures/lookup_first/promotion-gate-v1.json).
It expects the reference `acme` graph from the lookup-first fixture seed. Run
it against a trusted local control plane after loading the corresponding graph:

```bash
sekaictl admin evaluation lookup-first-gate run \
  tests/fixtures/lookup_first/promotion-gate-v1.json \
  --namespace acme \
  --target ./data/sekai.sock
```

The command exits `0` only for `allow` and exits `7` for `deny`. JSON output is
available with `--json`. The response contains case paths, refusal reasons,
bounded details, the suite digest, and the audit decision id; it never returns
the lookup answer or any provider content.

Each case declares its evaluation principal. The server requires every declared
principal to have read access to the suite namespace, then executes that case
under the declared principal. This keeps the gate representative of ordinary
route authorization while preventing an operator from testing an inaccessible
principal context. Avoid `root` and `local` case actors when the suite is meant
to validate production route behavior; those principals intentionally bypass
object grants. It records action `lookup_first.gate` with the suite digest, a
digest of bounded case results, counts, namespace, and verdict. The raw suite
remains an operator artifact and is not copied into audit evidence. Inspect the
decision through the existing audited decision read surface.

## Promotion boundary

A passing gate is evidence for an explicit operator apply. A failing gate
leaves the prior route policy unchanged. The gate command has no `--apply`
mode and cannot silently mutate `SetNamespacePolicy`; policy application stays
a separate audited administrative action. This clean-break v1 contract does
not accept an older suite shape or provide a compatibility fallback.

The gate reuses the situation-specific evaluation boundary established by
[ADR 0011](decisions/0011-separate-invariant-facts-and-evaluation-plans.md)
and the bounded execution policy in
[ADR 0012](decisions/0012-bound-stochastic-evaluation-by-situation.md). It is
specific to deterministic lookup-vs-golden evidence and does not replace
those evaluation-plan or Gunshi contracts.
