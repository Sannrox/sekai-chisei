# Research: fail-closed routing for structured capabilities

Issue: [#527](https://github.com/Sannrox/sekai-chisei/issues/527)

Related: [#175](175-lookup-vs-model-call.md), [#281](https://github.com/Sannrox/sekai-chisei/issues/281), [#525](https://github.com/Sannrox/sekai-chisei/issues/525), [#526](https://github.com/Sannrox/sekai-chisei/issues/526), [#529](https://github.com/Sannrox/sekai-chisei/issues/529)

Date: 2026-08-04

Status: **recommendation accepted — option 4 as a future gate; runtime unchanged**

## Decision

This issue closes as a research decision, not a runtime behavior change. The
accepted outcome is to defer any new cheap-default promotion until option-4
evidence exists, while preserving the existing route resolution. The phrase
"capable or operator-pinned" below describes the target for a future
promotion implementation; it is not a behavior delivered by #527.

The future policy target is:

- a new routing situation remains capable or operator-pinned until evaluation
  evidence authorizes a change;
- a complete, authorized lookup may skip the model and return its deterministic
  structured result; and
- a lookup refusal, capability id, or keyword alone must not create a new cheap
  bias.

The current execution flow resolves a route before lookup-first evaluates the
structured request. On a refusal, the previously resolved route remains in
effect and the refusal is recorded; the refusal itself does not replan to
either the capable or cheap tier. Issue #527 does not change that flow. Any
future refusal override would be a separate implementation with its own
acceptance evidence.

The target boundary for any newly introduced cheap signal is that it is
available only through explicit and eval-aware controls: an operator or
namespace policy may pin a route, and an existing cheap-eligible task class may
receive a cheap bias only when the applicable evaluation safety checks allow
it. The current runtime does not enforce that boundary in full: its
`complexity_route` heuristic is an additional cheap-bias path and remains
unchanged by #527.

This selects **option 4, eval-gated promotion only**, while preserving the
already-approved deterministic lookup-first exception. It keeps the desired
policy and current runtime distinct:

| Request state | Recommended policy outcome | Current/runtime boundary |
| --- | --- | --- |
| Complete authorized structured lookup | `lookup_hit`; no provider call | Implemented by lookup-first; the control plane has the complete answer under a fixed contract. |
| Incomplete, unauthorized, cross-namespace, schema-miss, or truncated lookup | Preserve the route selected before lookup-first and record `lookup_refusal`; do not add a cheap bias from the refusal | Current behavior preserves the pre-resolved route. This recommendation does not claim a capable fallback. |
| Explicit operator route or policy pin | The governed pinned route | Existing routing remains inspectable and still passes privacy, budget, residency, and availability checks. |
| Existing cheap-eligible task class | Cheap bias only when eval/regression safeguards permit it | This is the target boundary; current `complexity_route` can also bias short specs and is not changed here. |
| Open-ended natural-language request | Keep the existing capable/default boundary; do not add lookup substitution | The request is not a structured lookup contract; #527 does not change its current route resolution. |

## Evidence and boundary inventory

The current implementation exposes several routing signals, which is why the
recommendation is recorded as a target plus an implementation gap:

- `src/chisei/pipeline.rs` uses `complexity_route` as a weak heuristic. It
  recognizes `lint`, `typo`, short specs, and a small set of complexity words;
  short specs can receive a cheap bias before the lookup-first refusal is
  known.
- `src/chisei/model_routing.rs` limits automatic cheap eligibility to the
  explicit task classes `background`, `bulk`, `batch`, `small_fast`, and
  `small-fast`. Unknown, primary, and reasoning work fail safe to capable.
- `src/grpc/chisei_service.rs` checks evaluation regressions and capable-tier
  overrides before applying cheap bias, and records only realized cheaper
  routing rather than intent alone.
- `src/chisei/privacy.rs` defines `TaskClass` as the privacy vocabulary
  `private` / `template_only`. It must not become a cost-routing taxonomy.
- [Research #175](175-lookup-vs-model-call.md) establishes that free-form
  natural-language lookup substitution would reverse the governed
  NL-to-model boundary. Fixed structured capabilities are the safe exception,
  provided authorization and completeness are rechecked.
- [#526](https://github.com/Sannrox/sekai-chisei/issues/526) makes substitution
  reporting durable, but explicitly does not support a fleet ROI or spend-
  percentage claim. The report is evidence for future decisions, not a reason
  to promote a route automatically.

The wrong-route risk is asymmetric: a capable model costs more, while a cheap
model that invents an answer can appear successful unless a structured
evaluation catches it. Existing route and evaluation controls therefore make
option 4 the smallest decision that is both explainable and reversible.

## Current implementation gap

`src/chisei/pipeline.rs` still classifies a specification shorter than 20 words
as a `cheap` complexity route, and that route can be resolved before
lookup-first records a refusal. The resulting request can therefore retain a
cheap model without the new structured-capability situation having passed the
recommended gate. This is a known mismatch between the accepted target policy
and current behavior, not an implementation delivered by #527.

Any work that enforces the target policy must decide how to remove or gate that
heuristic, preserve explicit operator controls, and test refusal routing. The
#529 v1 follow-up below is limited to lookup-vs-golden evidence and does not
silently resolve this runtime gap.

## Explicit non-actions for #527

These are constraints on future implementation, not claims that the current
runtime already enforces every one of them.

- Do not route by capability id alone after a lookup refusal.
- Do not add a second durable task taxonomy or overload privacy `TaskClass`.
- Do not turn keyword complexity into an authority or correctness signal.
- Do not implement free-form NL-to-lookup answers, graph summarization, or
  hybrid retrieval under this decision.
- Do not silently promote a namespace, provider, or model globally from one
  fixture suite.
- Do not claim savings percentages without a measured, authorized corpus.
- Do not change the public protocol, persistence schema, provider adapters,
  gateway/native split, or privacy/egress rules as part of #527.

## Follow-up and promotion boundary

Existing [#529](https://github.com/Sannrox/sekai-chisei/issues/529) is the
follow-up feature. Its v1 scope is the deterministic lookup-vs-golden arm:

1. run the allow-listed structured cases offline;
2. require structural equality for complete lookup hits;
3. leave the prior route policy unchanged when a case fails; and
4. require an explicit, audited operator apply for any resulting policy
   change.

Because this recommendation does not select a cheap-model generative arm,
#529 must not add one to v1. A future cheap-vs-capable model comparison would
need its own evidence, acceptance criteria, and design review before it could
change the default.

## Conclusion

The accepted research outcome is **defer new cheap-default promotion until an
eval-gated control authorizes it**. A complete lookup may bypass the model;
lookup refusal records evidence and preserves the route already selected by
governed routing, including an existing cheap bias. The capable-or-
operator-pinned rule is a future implementation target, not a current runtime
invariant. This closes #527's research question by documenting the target and
the gap, while making no runtime change. The durable implementation work is
the lookup-vs-golden promotion gate in #529; enforcing the target boundary or
adding a refusal-triggered replan requires its own implementation and
acceptance evidence.
