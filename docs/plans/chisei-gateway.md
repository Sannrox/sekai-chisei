# Chisei Gateway Privacy Enforcement

This plan documents how the privacy-preserving delegation chain applies to the HTTP gateway once that gateway surface is present in this repository.

## Required Behavior

The gateway only proxies to external upstreams, so every gateway request is treated as egress. Gateway enforcement must stay server-driven:

- Resolve the request identity from the `gateway_key` object.
- Read `task_class` from the key properties, defaulting to `private`.
- Allow the `x-chisei-task-class` header to override the key property for an individual request.
- Send `task_class` to `ResolvePolicy`.
- Deny sensitive/private requests when Chisei returns `PermissionDenied`.
- Call `CheckEgress` with `{ namespace, payload, provider, task_class }` before forwarding any external request.
- Return `403` and record `gateway.leak_blocked` when `CheckEgress.allowed=false`.

The gateway must not reimplement privacy rules. Chisei owns the data-class, task-class, safe-provider, and leak-check semantics.

## Fail-Closed Requirement

For this feature, `GATEWAY_GOVERNANCE_FAILURE=open` is unsafe when the gateway knows the project or key is sensitive. If the key or project is known sensitive and Chisei is unreachable, the gateway must fail closed even when the general governance failure mode is configured as open.

Residual gap: if Chisei is unreachable before the gateway can determine whether a key belongs to a sensitive namespace, the gateway cannot know that the project is sensitive. Production deployments should prefer fail-closed governance for privacy-sensitive keys.

## Current Server Hooks

The gRPC service exposes the hooks the gateway needs:

- `ResolvePolicy(namespace, preferred_runtime, preferred_model, task_class)` returns `PermissionDenied` for sensitive/private requests that resolve to unsafe providers.
- `CheckEgress(namespace, payload, provider, task_class)` evaluates the privacy gate and deterministic leak checker without exposing matched text.
- `chisei.privacy` audit decisions record gate, leak-check, and optional reviewer outcomes.

The current binary also exposes the provenance renderer:

```bash
cargo run -- gateway-report --egress --format csv
cargo run -- gateway-report --egress --format html
```

## Residual Template-Inversion Risk

Template-only requests can still leak intent if the abstract task is too specific. Deterministic rules block known literals and configured patterns, but they cannot prove that a request is semantically harmless. `LEAK_REVIEW_MODEL` enables an optional local advisory reviewer that can warn and audit when an abstract request appears to reveal sector, position, timing, or proprietary intent. That reviewer is advisory only; deterministic leak rules remain the hard gate.
