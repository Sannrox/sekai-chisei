# ADR 0019: Keep native discovery and the HTTP provider matrix as separate catalogs

- Status: proposed
- Date: 2026-08-13
- Owners: @Sannrox
- Discussion: standing contracts High after [PR #608](https://github.com/Sannrox/sekai-chisei/pull/608)
- Supersedes: none
- Superseded by: none

## Context

After the gateway decide lifecycle landed in PR #608, two documents still
shared the name "capabilities":

- `SekaiService.DiscoverCapabilities` returns a namespace- and ACL-filtered
  catalog of governed Sekai/Chisei surfaces. Contract version `1.0`.
  `product_tier` selects core/advanced/experimental. Visibility is not a grant.
- `GET /v1/chisei/capabilities` returned the full unscoped
  `CapabilityMatrix` to any authenticated gateway caller. The matrix version
  was already `chisei.provider-capabilities/v1`, but the HTTP path and docs
  invited confusion with native discovery.
- `DecideGatewayExecution.capability_requirements_json` deserializes
  `provider_profile::CapabilityRequirements` (the same provider-capability
  family). Submitting a native catalog page parsed as `InvalidArgument` and
  became `policy_denied` instead of `capability_unsupported`.

Dumping every registered provider profile on HTTP GET leaked authority: callers
could observe experimental or unconfigured providers they could not route.
Scoping that HTTP GET to DiscoverCapabilities ACL/namespace (option a) would
have mixed two catalogs with different owners and shapes.

Reserved-kind hiding on authorized graph reads ([PR #612](https://github.com/Sannrox/sekai-chisei/pull/612))
is a separate High and is out of scope here.

## Decision

Keep two catalogs (option b). Do not treat the HTTP GET as
`DiscoverCapabilities`.

- Native discovery remains `DiscoverCapabilities` contract `1.0`, namespace +
  ACL + `product_tier`. Visibility is not a grant.
- HTTP `GET /v1/chisei/capabilities` is the provider-profile matrix
  `chisei.provider-capabilities/v1`. The response repeats that version on
  `x-chisei-capability-catalog`. `grant_semantics` is always `false`.
- The HTTP matrix includes only providers the current gateway snapshot can
  route: configured, routable, and not disabled or unpromoted experimental.
  It must not dump every registered profile.
- Decide `capability_requirements_json` accepts only
  `CapabilityRequirements`. A native catalog page or the HTTP matrix document
  in that field is `capability_unsupported`, not `policy_denied`.
- Do not invent OpenAPI. Document the versioned JSON contract in
  `docs/capability-catalog.md`.

## Alternatives considered

- **(a) Scope HTTP GET to DiscoverCapabilities ACL/namespace/decision
  posture.** Rejected: the HTTP document describes provider protocol features,
  not governed object/query/action surfaces. Applying native ACL to it would
  still mix catalogs and would not produce a usable provider matrix.
- **Leave HTTP as an unscoped dump and document the distinction only.**
  Rejected: authenticated-but-undecided callers would still receive every
  provider profile, which is leaked authority if the matrix is treated as
  grants.
- **Rename the HTTP path.** Not required for this contract revision. The
  versioned document and header disambiguate the existing path used by
  Responses hosts.

## Consequences

Gateway hosts continue to call `GET /v1/chisei/capabilities` for provider
features. They must not feed that JSON, or a native catalog page, into decide
requirements. Native SDKs continue to call `DiscoverCapabilities` and remain
unrelated to the HTTP matrix.

HTTP clients that previously parsed experimental or unconfigured profiles
from GET will stop seeing them until those providers are configured and
lifecycle-admitted. That is intentional.

## Validation

- `CapabilityRequirements::parse_json` rejects native catalog JSON and the
  provider matrix document.
- `DecideGatewayExecution` maps those mixes to `capability_unsupported`.
- `CapabilityMatrix::public_discovery` omits unconfigured and experimental
  profiles; `GET /v1/chisei/capabilities` serves that view.
- `docs/capability-catalog.md` names both contracts and the decide deny class.
