# ADR 0017: Return the repository to Apache 2.0

- Status: accepted
- Date: 2026-08-04
- Owners: @Sannrox
- Discussion: Direct maintainer approval in the implementation task (2026-08-04)
- Supersedes: none
- Superseded by: none

## Context

The repository was re-licensed from Apache 2.0 to AGPL-3.0-only in July 2026.
An intervening change dual-licensed the separately versioned `sekai-client`
and `sekai-proto` crates under Apache-2.0 or AGPL-3.0-only while leaving the
workspace default AGPL. The product is a local-first governance control plane
with public gRPC and HTTP entry paths, reusable protocol, client, provider,
gateway, and ontology crates, and a documented enterprise extension boundary.
The current workspace metadata targets version `1.0.0`, while the repository's
released tags still end at `v0.2.1`.

AGPL network copyleft is valuable when the project must require modified
network deployments to offer corresponding source to their users. It also
creates additional adoption and integration friction for organizations that
want to embed the control plane, build commercial extensions, or reuse the
public crates. The product direction prioritizes an adopted, interoperable
control-plane boundary over requiring reciprocity from hosted derivatives.

This decision assumes the maintainer confirms that the project copyright is
held or assigned to the entity relicensing the work. Git history is evidence
for investigation, not a substitute for that ownership review.

## Decision

License the repository's original work under the Apache License, Version 2.0,
using the SPDX identifier `Apache-2.0` in the root package and every workspace
crate. Update the repository license, contributor terms, public documentation,
and decision hierarchy to match. Remove the now-redundant dual-license-only
`LICENSE-APACHE` artifact.

This applies to new releases from the change boundary onward. Existing releases
that were published under AGPL-3.0-only retain that license; this decision does
not withdraw rights already granted to their recipients. Dependency licenses
remain governed by those dependencies and are not changed by this ADR.

## Alternatives considered

- **Keep AGPL-3.0-only:** preserves the strongest source-sharing incentive for
  modified network deployments, but conflicts with the project's adoption,
  reusable-crate, and enterprise-extension goals.
- **Dual-license AGPL-3.0-only and Apache-2.0:** offers downstream choice, but
  removes the network-reciprocity guarantee for users selecting Apache and
  leaves more license-selection complexity in the project.
- **Split licenses by crate:** could make the SDK and protocol permissive while
  keeping the server copyleft, but introduces boundary and composition rules
  that are harder for integrators to understand and maintain.

## Consequences

Apache 2.0 makes the public crates and control-plane implementation easier to
reuse in proprietary or open deployments, including commercial extensions. It
also means a hosted operator may modify and run the control plane without an
AGPL network-source offer, so the project cannot rely on license reciprocity to
ensure hosted improvements return upstream.

The change has no runtime, protocol, persistence, authentication, authorization,
or migration behavior. It requires synchronized package metadata and user-facing
license references, plus a clear release boundary so downstream users can tell
which versions remain AGPL-licensed.

## Validation

- Every workspace package reports `Apache-2.0` through Cargo metadata.
- Repository references to the project license agree with `LICENSE` and the
  contributor terms.
- The ADR is indexed from `docs/decisions/README.md`.
- `cargo fmt --check`, `cargo test --locked`, and
  `cargo clippy --all-targets -- -D warnings` remain green.
- Before publishing a new release, the maintainer confirms the copyright and
  employer-assignment chain for all incorporated contributions.
