# Research: can a model call reach a provider without admission

Issue: [#2279](https://github.com/Sannrox/sekai-chisei/issues/2279)
Date: 2026-11-14
Status: **recommendation complete** — see [ADR 0151](../decisions/0151-chisei-admits-every-model-call.md)

## Decision question

In a governed turn, which component issues the call to the model provider, and
is there any configuration in which a caller holding provider credentials
reaches a model without the plane admitting that call?

## Hypotheses

1. The plane issues every call. Callers never hold provider credentials.
2. The plane admits and the runtime calls, presenting a short-lived grant the
   provider-facing component verifies.
3. Today both exist, plus a path where a runtime configured with its own
   credentials calls directly.

## Evidence

### Caller-initiated paths

| Path | Constructs the provider request | Checked before contact | Recorded after |
| --- | --- | --- | --- |
| Native `PlanExecution` / `ExecutePlanStream` | Chisei `provider_execution` via `chisei-provider` | Namespace policy, residency, privacy/egress, hosted re-admission, then `EnterpriseExtension::admit_model` when an extension is installed (`src/grpc/chisei_service/native_execution_lifecycle.rs`, `src/grpc/provider_execution.rs`) | Operation receipt, budget, audit |
| Native content stream | Same `execute_native_content_request_stream` | Same as native chat | Operation receipt |
| Gateway HTTP (`/v1/responses`, `/v1/chat/completions`, `/v1/messages`) | Gateway `apply_provider_auth` after `DecideGatewayExecution` | Live `gateway.decide/v2` allow; missing or denied decide returns before upstream (`crates/chisei-gateway/src/gateway_proxy.rs`, `gateway_decision.rs`) | `RecordUsage`, receipts |
| Hosted embedding catch-up | `GuardedEmbedder` wrapping the OpenAI-compatible embedder | Live hosted-route re-admission and privacy screen on every `embed` (`src/grpc/chisei_service/embedding_route.rs`) | Embedding catch-up audit |

Gateway-owned keys (`OPENAI_API_KEY` and siblings) and same-provider passthrough
both still require `DecideGatewayExecution`. Passthrough forwards the caller's
provider header only after that allow (`docs/gateway.md`,
`upstream_auth_mode`).

`caller_provider_credentials_do_not_reach_upstream_without_admission` in
`crates/chisei-gateway/src/gateway_tests.rs` sends a valid caller OpenAI bearer
with process keys present and no control-plane target; the gateway returns
`503` and the fake upstream sees zero requests. The sibling
`fail_closed_blocks_when_chisei_preflight_is_unavailable` covers gateway-owned
keys with an unreachable plane.

### Plane-issued operator jobs

Leak review, scoring judge, and bounded stochastic evaluation construct
`llm::ChatRequest` with process keys (`privacy_egress.rs`, `scoring.rs`,
`stochastic_evaluation.rs`). They are not tenant routes and skip
`admit_model` ([tenant-provider-credentials](../tenant-provider-credentials.md)).
They run as Chisei jobs after a parent turn or operator schedule; they are not
a caller-held credential path.

### Outside the product

[ADR 0008](../decisions/0008-gateway-is-a-fail-closed-translator.md) already
records that operators may point clients at providers directly. That is an
explicit fallback with no receipts or policy. `chisei-provider` remains
internal execution machinery ([VISION.md](../../VISION.md)); using the crate as
a library is not a governed entry path.

## Recommendation

Hypothesis 2, with the native process also acting as the runtime after its own
admission: **Chisei is the single admission point**. After an allow, either
Chisei or the gateway issues the provider HTTP. No in-product configuration
lets a caller-held provider credential reach a model without that allow.

No follow-up feature issue: no bypass path was found.
