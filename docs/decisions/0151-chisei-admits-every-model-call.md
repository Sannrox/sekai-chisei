# ADR 0151: Chisei admits every model call

- Status: superseded by ADR 0152
- Date: 2026-11-14
- Owners: @Sannrox
- Discussion: none, resolved in Issue #2279
- Issue: #2279
- Supersedes: none
- Superseded by: [ADR 0152](0152-gateway-is-the-model-egress-layer.md)
- Related: [ADR 0008](0008-gateway-is-a-fail-closed-translator.md)

## Context

[#2279](https://github.com/Sannrox/sekai-chisei/issues/2279) asked which
component issues a governed model call and whether a caller holding provider
credentials can reach a model without Chisei admission. The plane is not a
general model proxy. Native clients use `PlanExecution` /
`ExecutePlanStream`; compatibility clients use the gateway. Provider adapters
are internal machinery.

## Decision

1. **Chisei is the single admission point for model calls.** Gateway HTTP is
   admitted by `DecideGatewayExecution` (`gateway.decide/v2`). Native
   execution is admitted by plan and execute on the same plane (policy,
   residency, privacy/egress, hosted re-admission, and
   `EnterpriseExtension::admit_model` when an extension is installed).
   Hosted embedding catch-up re-admits the live route before every outbound
   embed.
2. **After an allow, the process that already holds the request issues the
   provider HTTP.** The gateway translates and contacts the provider. Native
   execution uses `provider_execution` and `chisei-provider` in the Chisei
   process. There is no separate grant token the provider-facing component
   verifies.
3. **Caller-held provider credentials do not skip admission.** Same-provider
   passthrough forwards the caller's header only after `DecideGatewayExecution`
   allows. Gateway-owned process keys are applied the same way.
4. **Direct client-to-provider configuration stays outside the product**, as
   ADR 0008 already records. It is an operator fallback, not a plane mode.

## Alternatives considered

- **The plane issues every call and callers never hold provider credentials.**
  Rejected: same-provider passthrough is a supported gateway mode, and the
  gateway (not Chisei) issues those HTTP requests after admission.
- **A short-lived grant the provider-facing component verifies.** Rejected:
  no such grant exists. Admission is the live Chisei decision; the issuer
  then uses resolved or passthrough credentials.
- **Treat process-key operator jobs (leak review, scoring, stochastic eval)
  as a bypass.** Rejected: they are plane-issued, not caller-held credential
  paths, and are already documented as non-tenant routes.

## Consequences

Governed entry stays two doors into one PDP. A missing, denied, or
unavailable Chisei decision fails closed before provider contact, including
when the caller presents a valid provider bearer. No new admission mechanism
is added.

## Validation

- `caller_provider_credentials_do_not_reach_upstream_without_admission`
- `fail_closed_blocks_when_chisei_preflight_is_unavailable`
- Native hosted `admit_model` tests in `src/grpc/provider_execution.rs`
- Research notes: [2279-model-call-admission.md](../research/2279-model-call-admission.md)
