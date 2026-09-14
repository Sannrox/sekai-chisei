# ADR 0076: One compiling policy decision point over shipped v1 vocabularies

- Status: accepted
- Date: 2026-09-14
- Owners: @Sannrox
- Discussion: https://github.com/Sannrox/sekai-chisei/discussions/903
- Issue: https://github.com/Sannrox/sekai-chisei/issues/884 (#884)
- Supersedes: none
- Superseded by: none
- Related: [ADR 0025](0025-storage-enforced-object-security.md),
  [ADR 0027](0027-explicit-property-grants.md),
  [ADR 0038](0038-property-level-reads.md),
  [ADR 0049](0049-value-instance-access.md)

## Context

Namespace grants, markings, purpose, property grants, and row predicates each
have storage and an evaluator. [ADR 0025](0025-storage-enforced-object-security.md)
already compiles object-security v1 into storage predicates. Closest
composites still omit layers. Issue #884 asked for one decision point.

## Decision

1. Every public object read and write goes through one crate-visible function
   that **compiles** the already-shipped vocabularies into storage predicates
   before materialization. Mandatory markings stay mandatory. Discretionary
   grants, purpose, property, and value-instance rules narrow after that.
2. A documented wrapper that calls today’s evaluators in order is the
   **migration**, not the product.
3. This ADR does not adopt a new policy language or an out-of-process
   authorization service.
4. Simulation is a read projection over activation digests. It is not a
   grant. Audit records class, namespace, activation digest, and outcome —
   not hidden values.

## Alternatives considered

- Embed a new general-purpose policy language. Rejected: a second policy SoR.
- An external authorization service. Rejected: air-gap and authority leave
  the plane.

## Consequences

#885 implements the entry point, simulation, and audit query. v1 rule
semantics do not change. Combined-compile latency may pick an implementation
later; it does not pick a language.

## Validation

Existing object-security, grant, purpose, and property-grant suites pass
through the one entry with identical allow/deny. A path that omitted a layer
before now fails closed. No external process is required for community
runtime.
