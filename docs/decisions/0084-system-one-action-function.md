# ADR 0084: Bind System One as an Action-filling Function

- Status: accepted
- Date: 2026-09-17
- Owners: @Sannrox
- Discussion: https://github.com/Sannrox/sekai-chisei/discussions/974
- Issue: https://github.com/Sannrox/sekai-chisei/issues/975 (#975)
- Supersedes: none
- Superseded by: none
- Related: [ADR 0020](0020-shared-type-revisions-and-object-sync.md),
  [ADR 0063](0063-object-action-describe-preview.md),
  [ADR 0072](0072-in-process-function-host.md),
  [ADR 0073](0073-source-and-action-objects.md)

## Context

TypeSafe Jev returns typed Choice, Score, and Noul answers. The chat
`Provider` contract and the OpenAI/Anthropic gateway cannot absorb that
shape. ADR 0073 already says typed objects come from a source mapping or a
versioned Action. Function results are not type-revision facts
([ADR 0020](0020-shared-type-revisions-and-object-sync.md),
[ADR 0072](0072-in-process-function-host.md)).

## Decision

1. Jev is a **Function** bound to a `GovernedActionType`. It is not a chat
   provider, not a source, and not an inbound Action body.
2. The Action type's closed parameter schema **is** the answer space.
   `Choice` maps to a string enum; `Score` and `Noul` map to numbers.
3. Function input is an **authorized object projection**. Ungranted
   properties never leave the object.
4. `PreviewObjectAction` may fill `proposed_parameters_json` when the
   caller sends empty parameters and the type has a bind. Preview does not
   persist ([ADR 0063](0063-object-action-describe-preview.md)).
5. `SubmitActionInstance` remains the only write.
6. The bind pins an exact model id. `jev-latest` is refused.
7. Hosted TypeSafe is opt-in. Missing `TYPESAFE_API_KEY` fails closed.
   Ontology guest functions stay out of scope ([ADR 0072](0072-in-process-function-host.md)).

## Alternatives considered

- Register Jev as a chat provider. Rejected: it cannot generate text,
  tools, or streams.
- Add inbound `/v1/systemone` on the gateway. Rejected: a thin proxy and a
  second write path.
- Wait for the guest function sandbox. Rejected: this Function is
  plane-owned System One, not customer code.

## Consequences

Action types may carry additive `system_one` metadata. Old types ignore
it. Preview gains an additive `proposed_parameters_json` field. Domain
question lists stay in namespace-scoped types, not the core ontology.

## Validation

Fixture answers must validate against a real Action parameter schema.
Preview with those parameters must not create an instance or mutate the
object. Ungranted properties must not appear in Function `state`.
