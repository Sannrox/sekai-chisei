# Governed requirement and invariant facts

Issue: [#462](https://github.com/Sannrox/sekai-chisei/issues/462).
Decision: [ADR 0011](decisions/0011-separate-invariant-facts-and-evaluation-plans.md).

The `sekai.governed-facts/v1` profile represents immutable requirements,
invariants, and scoped waivers as Sekai-owned facts. It is domain-neutral:
integrations choose opaque subject profiles and references, while the core
contract contains no repository, ticket, release, deployment, or source-code
fields.

This is not an evaluator API. Invariants describe normative meaning,
applicability, and a verification contract. Chisei evaluation plans select the
approved evaluator implementations that can satisfy those contracts.

## Public read surface

The 1.0 wire is intentionally read-oriented. Profile and immutable fact
versions are established by the governed-data bootstrap and pipeline paths;
there is no public CRUD endpoint for authoring them. The profile and every fact
use the existing graph and object-change audit surface rather than a separate
requirements database.

`GetGovernedFactVersion` reads one authorized immutable fact version by object
ID. `ResolveInvariantSet` is the bounded evaluation-facing projection described
below.

Each version binds:

Every version binds:

- namespace, stable logical identity, exact version, statement, and canonical
  content digest;
- a closed immutable `active` or `retired` lifecycle status;
- one or more opaque subject profiles and optional exact subject references;
- provenance through the authenticated actor, `source_ref`, and exact projected
  `external_evidence` object references;
- an explicit effective time and optional exact predecessor;
- an optional classification marking; and
- for invariants, a situation-specific predicate kind, input/result schemas,
  evidence types, and exact requirement-version references.

Requirements cannot carry invariant verification fields. Invariants may not
embed code, expressions, provider configuration, or an evaluator selection.

The first version has no predecessor. Every later version of the same logical
fact names the exact current version in `supersedes_object_id`. Generic object
CRUD, listing, traversal, update, and deletion hide or reject these reserved
objects. Conflicting replay and branching histories fail closed.

An `active` version participates in set resolution. A `retired` successor
supersedes the prior version but is not returned as an applicable normative
fact, providing an append-only retirement path.

Evidence references are exact IDs of projected `external_evidence` graph
objects, not external URLs, payloads, or credentials. The writer must be
authorized to read every referenced requirement, predecessor, and evidence
object.

## Resolve an authorized invariant set

`ResolveInvariantSet` requires an explicit namespace, subject profile, opaque
subject reference, evaluation time, and bounded item limit. It returns:

- applicable, non-superseded requirement and invariant versions;
- applicable, unexpired waivers that reference an active returned invariant;
- a profile digest; and
- a canonical set ID and digest binding the exact subject, time, and returned
  versions.

Resolution is authorization filtered before canonicalization. A fact is omitted
when it or any exact requirement, predecessor, or evidence reference is not
visible to the caller. Hidden records therefore do not alter returned counts,
documents, or the caller's set digest. A visible invariant is also omitted when
its exact requirement version is no longer active at the requested time.
Reference visibility is cached across the complete request and capped at 8,192
unique object checks; exceeding that operational bound fails with
`resource_exhausted`.

The resolver never falls back to `latest`, another version, another evidence
object, or an allow result. Corrupt or contradictory visible history, invalid
input, and bounds exhaustion fail explicitly.

## Classification and ACLs

Fact reads use both graph ACLs and the optional `access_marking` lattice. Use
ordinary object grants to restrict a reserved fact object after creation.
Callers without access receive `not_found` from exact reads. Set resolution
projects only the caller-visible reference closure.

Do not put secrets, credentials, raw artifact payloads, or unrestricted
diagnostics in statements, source references, waiver rationales, or evidence
identifiers.

## Persistence, backup, and rollback

SQLite and PostgreSQL share the same graph/audit implementation and conformance
fixture. No schema migration is introduced by this profile. Normal graph
backup, restore, and audit verification cover the records.

Rollback does not mutate or delete versions. Publish a new immutable version
that supersedes the current one, or resolve an earlier explicit evaluation time.
Historical receipts and manifests should retain exact object IDs and content
digests, so they continue to identify the original versions after
supersession.

The runnable
[`governed_fact_profile`](../examples/governed_fact_profile.rs) example seeds
API-compatibility and data-migration-safety facts through the same profile
without adding either domain to the core vocabulary.
