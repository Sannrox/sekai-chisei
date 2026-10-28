# Impact route policy

`chisei.impact-route/v1` is an opt-in rule on a namespace route policy. It
maps the impact class of a model call to the models that call may use, so an
expensive model can be kept for high-impact work without trusting the caller
to pick a namespace or a model.

The rule is supplied as canonical JSON in
`SetNamespacePolicyRequest.impact_route_policy_json` and persisted with the
namespace policy object, which is the only copy: every planning, execution
and gateway decision reads the rule from it, so all instances on one store
enforce the rule as last written. An empty value keeps the rule as currently
stored (the update is a compare-and-set on the policy object, so a
concurrent update cannot drop it), and the JSON value `null` clears it. A malformed rule, an unknown class, a missing
`unclassified` entry, or an entry that allows nothing is rejected. A stored
rule that no longer parses refuses every model call in the namespace instead
of routing without it. A namespace without the rule routes exactly as before.

## Rule shape

```json
{
  "contract_version": "chisei.impact-route/v1",
  "routes": {
    "unclassified": {"allowed_models": ["native-default"]},
    "routine": {"allowed_models": ["native-default"]},
    "high_impact": {
      "allowed_models": ["native-default", "gpt-5.5"],
      "allowed_families": []
    }
  }
}
```

`routes` keys are `routine`, `high_impact` and `unclassified`; the
`unclassified` entry is required. A model matches an entry when it has the
same identity as one of `allowed_models`, or belongs to one of
`allowed_families` (a provider id, or a model-id prefix family as for model
family enablement).

## Which entry applies

The caller never declares a class. A model call may cite an Action Work claim
(`ExecutionInput.action_claim` or `DecideGatewayExecutionRequest.action_claim`).
When that claim is live and held by the calling principal in the call's
namespace, the call takes the claimed Action type's `impact_class` (see
[Governed Action types](governed-action-types.md)). Everything else is
unclassified: no claim, a stale generation or token, an expired lease, a
claim held by another principal, an Action type without a class, and any
claim the Chisei plane cannot verify. A class without its own entry uses the
`unclassified` entry. Citing a claim can therefore narrow or keep a route but
never widen it beyond what the claim proves.

## Composition with routing and admission

The rule narrows the namespace policy's `allowed_models` to the ones the class
may use, and drops the namespace default when the class may not use it.
Routing aliases (`cheap`, `capable`, `ollama/cheap`, ...) stay in the narrowed
policy, and the router ranks only candidates the class permits, so an alias
or the fallback for an unavailable model resolves to a permitted model. An
alias with no permitted candidate is refused. Every later step routes inside
that narrowed policy: cost tiers, local-free fallback, portfolio routing and
gateway fallback models; the resolved model is checked again at the end. Model
family enablement and model admission then run as before. The most
restrictive layer wins; the rule never enables a family or admits a model.

- A requested model the class may use is kept (`allowed`).
- A requested model it may not use is replaced by the namespace default when
  the class may use the default; this is the router's usual substitution
  (`substituted`).
- Otherwise the call is refused (`refused`): no allowed default, a route
  override the class may not use (an override is an exact pin and is never
  substituted), or a resolved model outside the class.

Refusals start with `impact route denied`. Planning returns
`INVALID_ARGUMENT` and writes a `chisei.impact_route` decision. Gateway decide
denies with `policy_denied`.

Native and content execution resolve the claim again just before the model
call and apply the rule to the planned model. A plan whose claim lapsed after
planning, so the class may no longer use the planned model, is refused with
`FAILED_PRECONDITION` and a receipt outcome of `impact_route_denied`; plan
again.

## Audit

When the rule applies, the plan carries `impact_route_class` and
`impact_route_decision`, and the receipt's policy and model call events (or
the refusal's outcome event) and the gateway decision record carry
`impact_route_applied=true`, `impact_route_class` and
`impact_route_decision`. A call that cites a claim in a namespace without the
rule records `impact_route_applied=false`. The claim attributes from
[Governed Action types](governed-action-types.md) are recorded alongside.

## Compatibility

The field and the stored property are additive. A plane that predates the
rule ignores it and routes by the namespace policy alone, so finish a rolling
upgrade before relying on the rule; an older plane's `SetNamespacePolicy`
also rewrites the policy object without the rule.
