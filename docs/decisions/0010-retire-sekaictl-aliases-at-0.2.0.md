# ADR 0010: Retire deprecated `sekaictl` aliases at `0.2.0`

- Status: accepted
- Date: 2026-07-29
- Owners: @Sannrox
- Discussion: https://github.com/Sannrox/sekai-chisei/issues/449
- Supersedes: [ADR 0009](0009-sekaictl-administration-hierarchy.md) (compatibility window only)
- Superseded by: none

## Context

[ADR 0009](0009-sekaictl-administration-hierarchy.md) grouped expert
operations under `sekaictl admin` and required both a `0.2.0` minor-release
boundary and at least 90 days of alias availability before removing the old
top-level paths.

The grouped paths shipped on 2026-07-29. A release-boundary adoption audit found
no evidence of a sizable public user base: the public repository had two stars,
no forks or watchers, one release without downloadable assets, and no public
downstream code references to the deprecated credential path. Private source
clones and deployments remain unobservable because the project has no usage
telemetry.

The 90-day requirement therefore protects hypothetical adoption rather than
known consumers. Keeping it would delay a deliberate breaking cleanup beyond
the already-signaled `0.2.0` compatibility boundary.

## Decision

Keep all deprecated expert top-level aliases for every `0.1.x` release. Remove
them in `0.2.0`; do not require a separate minimum-90-day availability window.

The removal must retain the nine canonical root choices, provide bounded help
that names the canonical replacement for each removed alias, and publish an
explicit old-to-new command mapping in the `0.2.0` release notes.

This amendment changes only the retirement timing in ADR 0009. Its canonical
hierarchy, server-authority boundary, stderr-only warning behavior during
`0.1.x`, and shared-handler requirements remain accepted.

## Alternatives considered

- Keep the 90-day minimum: rejected because observable adoption is minimal and
  `0.2.0` is already the declared breaking boundary.
- Remove aliases during `0.1.x`: rejected because it would violate the
  published compatibility promise.
- Retain aliases indefinitely: rejected because permanent duplicate command
  paths preserve the complexity the hierarchy change was intended to remove.

## Consequences

Operators on `0.1.x` retain the exact compatibility period already promised by
semantic versioning. Upgrading to `0.2.0` requires migrating expert commands to
their canonical `admin` paths. The project accepts residual uncertainty about
unobservable private consumers and mitigates it with deprecation warnings,
bounded migration help, and release notes.

## Validation

- Issue #448 is closed and maintained repository usage uses canonical paths.
- The public adoption audit is recorded in issue #449 and this ADR.
- Alias-removal tests and release notes remain acceptance requirements for
  issue #449.
