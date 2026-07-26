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
- **Namespace authorized**: gRPC requires team-namespace access.
- **Audited**: each dry-run records a `policy.dry_run` decision with counts and
  the candidate policy version.
- **Bounded**: at most 5,000 receipts; sample operation IDs capped per delta
  class.

## Delta classes

| Class | Meaning |
| --- | --- |
| `unchanged` | Candidate preserves the historical allow/deny and route |
| `re_routed` | Candidate would allow but select a different runtime/model |
| `would_deny` | Historical allow would become deny under the candidate |
| `would_allow` | Historical deny would become allow under the candidate |
| `insufficient_history` | Receipt lacks enough route/policy metadata |

## gRPC

```text
DryRunNamespacePolicy
  namespace, start_timestamp_ms, end_timestamp_ms
  allowed_runtimes, allowed_models, default_runtime, default_model, data_class
  request_id (optional)
```

Response includes aggregate counts, bounded samples per delta class, and a
capped per-receipt result list.

## Non-goals

- Full agent trajectory re-execution
- Graph world-state counterfactuals (#148)
- Automatic policy apply from dry-run results
- Budget/egress/approval micro-simulation beyond route policy (v1 focuses on
  the namespace model/runtime policy surface)
