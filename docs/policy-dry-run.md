# Historical policy dry-run

Issue: [#282](https://github.com/Sannrox/sekai-chisei/issues/282).

## Purpose

Before activating a namespace policy revision, operators can dry-run a
**candidate** policy over stored operation receipts for a time window and see
how routes and allow/deny outcomes would have changed.

## Guarantees

- **No side effects**: does not call providers, redeem permits, mutate policy,
  or execute host tools.
- **Candidate only**: the supplied policy is never activated.
- **Namespace authorized**: the operator console requires namespace grant
  access (authenticated actor must hold a grant on the namespace boundary).
- **Audited**: each dry-run records a `policy.dry_run` decision with counts and
  the candidate policy version (RPC fails if audit persistence fails).
- **Bounded**: at most 5,000 receipts; sample operation IDs capped per delta
  class.

## Receipt requirements

Accurate dry-run needs `RouteSelected` attributes:

- `preferred_runtime` / `preferred_model` (effective pre-resolution preference)
- `runtime` / `model` (historical resolved route)

Historical allow/deny for this surface is inferred from whether a route was
selected. Composite `PolicyDecided.executable=false` (budget, privacy, eval,
etc.) is **not** treated as a namespace route-policy denial when a route exists.

New planned executions persist the **effective pre-policy preference** actually
fed into route resolution: request values when set, otherwise route override,
pipeline recommendation, route bias, or runtime fallback. This is not the same
as post-policy `runtime`/`model`. Older receipts without preferences are
counted as `insufficient_history`.

## Delta classes

| Class | Meaning |
| --- | --- |
| `unchanged` | Candidate preserves the historical allow/deny and route |
| `re_routed` | Candidate would allow but select a different runtime/model |
| `would_deny` | Historical allow would become deny under the candidate |
| `would_allow` | Historical deny would become allow under the candidate |
| `insufficient_history` | Receipt lacks enough route/policy metadata |

## Operator console

```text
The policy workspace invokes the bounded dry-run engine with
  namespace, start_timestamp_ms, end_timestamp_ms
  allowed_runtimes, allowed_models, default_runtime, default_model, data_class
  request_id (optional)
```

The rendered workspace includes aggregate counts, bounded samples per delta
class, and a capped per-receipt result list. The 1.0 public Chisei RPC surface
does not expose a separate dry-run endpoint.

## Live shadow

Issue: [#1630](https://github.com/Sannrox/sekai-chisei/issues/1630).

Dry-run replays history. A live shadow evaluates a candidate route policy
beside the active policy on every live policy resolution for the namespace,
both gateway decisions and native execution planning, so new traffic
patterns show up before activation.

- The RPCs are experimental: enable them with `SEKAI_EXPERIMENTAL_RPCS=1`
  or the `experimental-rpcs` build feature.
- `ChiseiService.StartPolicyShadow` takes the same route-policy
  fields as `SetNamespacePolicy`, plus `min_evaluations` (at least 1) and
  `min_match_rate_bps` (0 to 10,000). It replaces any shadow for the namespace
  with a new run (`shadow_id`) and an empty report. The candidate's own
  default must route.
- A resolution is observed for the first shadowed scope among its ranked
  policy scopes, up to the scope whose policy decided it. A namespace that
  has no policy of its own and inherits a later scope's policy is observed
  too, because activating its candidate would take over that traffic.
- Only the active decision takes effect. The candidate outcome is compared
  with the same delta classes as dry-run (`unchanged`, `re_routed`,
  `would_deny`, `would_allow`). A shadow read or write failure is logged and
  never fails or changes the live decision.
- `GetPolicyShadowReport` returns counts, the match rate, and at most 16
  samples per differing class. A report passes once at least
  `min_evaluations` decisions were evaluated and the unchanged share is at
  least `min_match_rate_bps`.
- `SetNamespacePolicy` with the shadowed candidate is refused with
  `policy_shadow_report_not_passing` until the report passes, or when the
  report was measured against a namespace policy that is no longer active.
  An admitted
  activation is recorded as `policy.shadow_activation` before the policy is
  written. After any `SetNamespacePolicy` for the namespace, the checked run
  ends, because the candidate is active or its baseline changed. A run left
  behind by a crash or a concurrent restart no longer matches its pinned
  baseline, so it is not observed again; stop or restart it.
- `StopPolicyShadow` ends a shadow explicitly.
- Start, stop, and admitted activation are recorded as `policy.shadow_start`,
  `policy.shadow_stop`, and `policy.shadow_activation` decisions before the
  state changes, so a failed audit changes nothing. All three
  RPCs require control-plane administration (`root` / `local`), like
  `SetNamespacePolicy`.
- State lives in `chisei_policy_shadow` on both community backends. Counters
  are updated atomically per run, so every instance resolving policy for the
  namespace adds to the same report, and a late observation for an ended run
  is dropped. A shadow whose namespace policy changed since it started is
  skipped.

A shadow pins the namespace's persisted policy version when it starts, and
activation checks it against the persisted version again. An admitted
activation claims its run for 60 seconds, and only while the stored counters
pass. Counting pauses during the claim, so the admitted report is the one
that was checked. `StartPolicyShadow` and `StopPolicyShadow` cannot replace
or remove a claimed run and return `ABORTED` instead. The claim is confirmed
again immediately before the policy write, which itself takes no fencing
token. A crash during activation leaves the claim to lapse. Concurrent
`SetNamespacePolicy` calls on different instances stay last-writer-wins.

A namespace without its own policy is compared against whichever inherited
policy decided each request. Its shadow pins only the absence of its own
policy, so a change to the inherited policy during the run is not tracked.

The comparison covers the namespace route policy only, like dry-run. Context
admission, privacy, budget, and evaluation gates are not shadowed.

## Non-goals

- Full agent trajectory re-execution
- Graph world-state counterfactuals (#148)
- Automatic policy apply from dry-run results
- Budget/egress/approval micro-simulation beyond route policy (v1 focuses on
  the namespace model/runtime policy surface)
