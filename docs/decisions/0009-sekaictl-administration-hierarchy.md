# ADR 0009: Group expert `sekaictl` operations under `admin`

- Status: accepted
- Date: 2026-07-29
- Owners: @Sannrox
- Discussion: https://github.com/Sannrox/sekai-chisei/issues/442
- Supersedes: none
- Superseded by: [ADR 0010](0010-retire-sekaictl-aliases-at-0.2.0.md) (compatibility window only)

## Context

The ontology-first product loop competed with advanced administration at the
root of a 20-command CLI. Research in
[#442](https://github.com/Sannrox/sekai-chisei/issues/442), landed through
[#446](https://github.com/Sannrox/sekai-chisei/pull/446), compared a flat
surface, journey verbs, capability-conditioned discovery, and a second binary.
The accountable maintainer accepted its recommendation on 2026-07-29.

## Decision

The canonical root hierarchy is:

```text
ontology launch doctor smoke models estimate receipt report admin
```

Expert access, gateway, governance, assurance, and federation operations live
under `sekaictl admin`. The complete command mapping is maintained in the
[#442 research artifact](../research/442-sekaictl-command-surface.md).

Existing expert top-level commands remain exact behavioral aliases throughout
all `0.1.x` releases. They remain available for at least 90 days after grouped
paths ship and may be removed only in `0.2.0` or a later minor release after a
repository and known-external-usage audit. Alias warnings, when introduced, go
only to stderr and do not alter machine-readable stdout.

CLI grouping never grants server authority. Authentication, authorization,
policy, approval, audit, and persistence remain owned and enforced by the
server.

## Alternatives considered

- Keep the flat surface: rejected because ordering does not reduce peer choices.
- Group by journey verbs: rejected because generic verbs split the coherent
  ontology workflow and require more core-path aliases.
- Capability-conditioned help: rejected because recovery commands must remain
  discoverable when a server is unavailable.
- Separate day-one binary: rejected because it duplicates packaging and
  configuration without reducing control-plane complexity.

## Consequences

Core journeys retain their command depth while root discovery falls from 20 to
9 choices. Expert operations add one meaningful navigation segment. During the
compatibility window, both canonical and alias paths must dispatch through the
same handlers, which adds characterization-test obligations but avoids a flag
day for scripts.

## Validation

- Characterization tests cover every canonical-to-alias mapping.
- Root help lists only the nine canonical choices.
- Gateway smoke and maintained automation prove handler behavior is unchanged.
- Before alias removal, a release-boundary usage audit must prove the version
  and 90-day gates are satisfied.
