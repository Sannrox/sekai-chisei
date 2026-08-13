# Context admission policy

`chisei.context-admission/v1` is a namespace-scoped policy for deciding how
already-authorized context projections may participate in native planning and
gateway execution. It governs use; it does not adjudicate truth, rewrite an
epistemic descriptor, or mutate evidence.

The policy is supplied as canonical JSON in
`SetNamespacePolicyRequest.context_admission_policy_json`. An empty value keeps
the currently stored policy, and the JSON value `null` clears it. A malformed
or unsupported policy is rejected; it never falls back to a weaker policy.

Gateway fat-decide fails closed when the namespace has no context-admission
policy, when the stored policy is corrupt or unavailable, and when no matching
operation-level rule exists and `default_action` or `unknown_action` blocks
provider execution. Native enrichment without a policy still preserves the
existing include behavior. Gateway setup seeds a default include/hold-out
policy so a configured gateway namespace can admit.

If a fat-decide request includes `pipeline_spec` after admission, a pipeline or
sampling error denies the request. The control plane does not continue with
`sampling_evaluated=false` and an empty prepared spec.

## Policy shape

```json
{
  "contract_version": "chisei.context-admission/v1",
  "default_action": "include",
  "unknown_action": "hold_out",
  "rules": [
    {
      "action": "hold_out",
      "evidence_statuses": ["contested", "insufficient"]
    },
    {
      "action": "qualify",
      "origin_classes": ["hypothesis"],
      "operation_risk": "high"
    },
    {
      "action": "require_review",
      "operation_risk": "critical"
    }
  ]
}
```

Rules are evaluated in order and the first matching rule wins. A rule can
select any combination of `origin_classes`, `evidence_statuses`,
`lifecycle_statuses`, `applicability`, `confidence_basis`, confidence bounds
(`min_confidence_bps`/`max_confidence_bps`), and minimum `operation_risk`
(`low`, `medium`, `high`, or `critical`). The action vocabulary is:

- `include`: use the projection as-is;
- `qualify`: use it with a bounded origin/evidence/lifecycle qualification;
- `hold_out`: omit it from enrichment while allowing the operation to proceed;
- `require_review`: retain it with a qualification for the reviewable plan,
  mark the operation for review, and block provider execution; or
- `require_verification`: omit it, require verification, and block provider
  execution.

`unknown_action` applies when a descriptor has an unknown origin, evidence, or
lifecycle dimension, or lacks producer confidence/basis. It defaults to
`hold_out`, so a configured policy never silently treats unknown metadata as a
fact. Operators may explicitly choose another action and that choice is part
of the content-addressed policy version.

## Boundaries and parity

Descriptors are read-only, authorized projections. The policy does not copy
source payload, reinterpret evidence, change lifecycle state, or bypass
namespace/classification/egress authorization. Stale, retracted, superseded,
contested, and insufficient sources retain their source semantics. Context is
evaluated before a provider call in both the native and shared gateway paths.
Gateway requests have no context descriptor, so only descriptor-free,
operation-risk rules are eligible there; descriptor-specific rules run in the
native enrichment path. This keeps the gateway conservative rather than
inventing metadata.

Native `ExecutionPlan` exposes the policy version, descriptor contract version,
bounded decision/reason codes, and admitted source digests. The planning and
`PolicyDecided` receipt events pin the same metadata. Gateway receipts record
the operation-level decision and bounded reasons; they never disclose hidden
descriptors or source counts. Review and verification outcomes are generic and
do not identify held-out content.

The policy is durable with the namespace policy object and is revalidated on
load. Configure it through the authenticated control-plane admin surface, then
inspect the returned policy version and execution receipt when testing a new
rule set.
