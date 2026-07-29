# ADR 0008: Keep the gateway a fail-closed protocol translator

- Status: accepted
- Date: 2026-07-29
- Owners: @Sannrox
- Discussion: https://github.com/Sannrox/sekai-chisei/issues/424
- Supersedes: none
- Superseded by: none

## Context

The OpenAI- and Anthropic-compatible gateway exists to translate client
protocols into governed provider requests. It accumulated independent
authorization modes: operation without a control-plane target, a no-preflight
escape hatch, cached last-known governance decisions, and duplicated policy and
budget calls. Those modes made the compatibility edge a second policy decision
point with its own outage semantics.

Issue [#418](https://github.com/Sannrox/sekai-chisei/issues/418) and
[PR #432](https://github.com/Sannrox/sekai-chisei/pull/432) established one
complete, versioned control-plane decision for configured gateway requests.
Issues [#424](https://github.com/Sannrox/sekai-chisei/issues/424),
[#425](https://github.com/Sannrox/sekai-chisei/issues/425), and
[#426](https://github.com/Sannrox/sekai-chisei/issues/426) identify the
remaining secondary authorization modes.

## Decision

The gateway is an optional protocol translator and policy-enforcement point,
not a policy decision point.

When the gateway is deployed:

- it requires a live Sekai Chisei control-plane target;
- every provider request requires one complete, live control-plane allow
  decision before provider contact;
- it validates and enforces the returned route, capabilities, classification,
  and budget outcome but does not derive them independently;
- unavailable, denied, malformed, or incompatible governance responses fail
  closed;
- cached or locally inferred decisions never grant outage authority; and
- durable recovery may preserve receipts, usage, and audit records, but never
  authorization.

Operators may omit the gateway and configure supported clients directly
against providers. That is an explicit fallback outside Sekai Chisei
governance, receipts, and policy enforcement; the gateway does not perform this
fallback automatically.

## Alternatives considered

- **Keep an ungoverned proxy mode.** This improves provider availability but
  silently removes the product's governance and receipt guarantees.
- **Use last-known decisions during outages.** This creates a second,
  time-bounded authorization system at the edge and cannot safely account for
  revocation or changing budget state.
- **Move policy, budget, and routing into the gateway.** This reduces a network
  dependency by duplicating the control plane and makes the gateway a second
  source of truth.
- **Require every client to use the gateway.** This makes a compatibility
  adapter mandatory even when a client can integrate with the control plane or
  provider directly.

## Consequences

Gateway startup and request handling become simpler and have one governed
operating model. Policy, budget, evaluation, routing, and outage authority have
one owner: the control plane.

The gateway cannot serve provider traffic while the control plane is
unavailable. Operators who prioritize provider availability over governance
must deliberately switch clients to direct provider configuration and accept
the loss of Sekai Chisei guarantees.

Removing no-preflight and last-known authorization is a breaking configuration
change. Recovery spools must be narrowed carefully so durable accounting and
receipt recovery remain intact.

## Validation

- Gateway startup fails without a configured control-plane target.
- Every provider contact is preceded by a live admitted decision.
- Control-plane failure, denial, or incompatible decisions produce no provider
  contact.
- Gateway code contains no locally authoritative policy, budget, evaluation,
  or routing fallback.
- Recovery tests prove receipt, usage, and audit durability without granting
  authorization.
- Cross-provider compatibility tests prove the gateway only translates routes
  authorized by the control plane and operator configuration.
