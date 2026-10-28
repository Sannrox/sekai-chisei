# ADR 0135: Ship security findings and exposures as a types-only domain package

- Status: accepted
- Date: 2026-10-28
- Owners: @Sannrox
- Issue: https://github.com/Sannrox/sekai-chisei/issues/1923 (#1923, part of #1668)
- Supersedes: none
- Superseded by: none
- Related: [ADR 0052](0052-capability-package-certification.md),
  [ADR 0073](0073-source-and-action-objects.md),
  [ADR 0095](0095-feedback-evidence-finding-package.md)

## Context

Security findings come from probes, reviews, scanners, agents, and advisories.
Each source keeps them in its own store. Issue #1668 asks for a governed record
of a finding, of its exposure on a deployed target, and later of the decisions
taken on it. This first slice covers findings and exposures. ADR 0095 already
settles how a domain package ships: types only, certified members, objects
written through governed Actions, and no domain-specific core RPC.

## Decision

1. The security package (`pkg:security.finding-exposure/v1`) is **types only**,
   following ADR 0095. It registers ontology classes, ObjectTypes, governed
   Action types, and an evaluation member. It certifies the `ontology`,
   `action_type`, and `evaluation` members. It packages no live instances and
   is not a runtime grant.
2. **Finding identity is its problem signature.** A finding is unique per
   namespace by `problem_signature`. A second report of the same problem is
   recorded as an **occurrence** of that finding. The finding Action refuses a
   duplicate signature and names the existing finding.
3. **Occurrence identity is the source occurrence id.** An occurrence is unique
   per namespace by `occurrence_id`, so a replayed observation never counts as
   a new occurrence. Replaying the same Action request stays the core
   idempotent no-op.
4. **Hypotheses are not measured facts.** A hypothesis is its own kind, disjoint
   from occurrences and exposures. An exposure verdict other than `unknown`
   must cite a measured occurrence of the same finding as `evidence_id`.
   Citing a hypothesis, or any other object, is refused.
5. **Exposure identity is the finding and the deployed target.** One exposure
   exists per finding, release, and environment. A verdict update cannot change
   that target.
6. Identities are stamped into `external_id` with a kind prefix and enforced at
   commit by a partial unique index on `(namespace, external_id)` for the
   finding, occurrence, and exposure kinds, on SQLite and PostgreSQL. This is
   the same primary-key analog as the feedback observation index. The
   plan-time checks only give a precise error.

7. **A disposition reopens when its basis no longer holds** (#1925). The
   exposure records the current facts of its target (dependency closure,
   release and configuration digests, reachable markings, advisory revision)
   through `security.exposure.basis`, which a connector or a transform
   write-back drives. A disposition whose basis differs from those facts, or
   whose expiry passed, is superseded by a `needs-review` disposition through
   `security.disposition.reopen`. Dispositions stay immutable. The reopen
   carries the basis unchanged and names the fact and its new value, and the
   validator refuses a reopen the facts do not warrant. Its object id derives
   from the disposition it reopens, and the successor index allows one
   successor, so a repeated or restarted pass reopens it once. Changes are
   found in the committed object-change feed, never by polling a source. The
   certification moves to `cert:security.finding-exposure/v1.2`. A server
   driver for these passes is #1954.

## Alternatives considered

- A findings store and domain RPC. Rejected for the same reason as ADR 0095: a
  second fact authority next to `SubmitActionInstance`.
- Counting occurrences in a property on the finding. Rejected: a counter cannot
  tell a replay from a new observation. A unique occurrence object can.
- One store-wide unique index on `(namespace, external_id)`. Rejected: empty
  and shared `external_id` values are common on other kinds.

## Consequences

Operators install and certify the package through the existing admin surfaces.
Fixture documents live under `tests/fixtures/security/`. Dispositions with a
validity basis (#1924) and their reopen on change or expiry (#1925) build on
these types.

## Validation

Crate tests install the fixtures into an in-memory runtime and cover:

- portable ontology import with validation and provenance
- package member certification
- a duplicate signature collapsing into one finding with several occurrences
- a replayed occurrence refused while the same request stays a no-op
- an exposure refusing a hypothesis, or an occurrence of another finding, as evidence
- a fixed exposure target
- a false positive reopened when its closure changes, with the fact in its
  receipt, and an expired disposition reopened once across a restart
- store-level uniqueness without the plan-time check
- concurrent duplicate findings keeping exactly one
