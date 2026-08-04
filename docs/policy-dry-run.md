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

## Non-goals

- Full agent trajectory re-execution
- Graph world-state counterfactuals (#148)
- Automatic policy apply from dry-run results
- Budget/egress/approval micro-simulation beyond route policy (v1 focuses on
  the namespace model/runtime policy surface)
