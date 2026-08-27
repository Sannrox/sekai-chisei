# ADR 0040: Generate revision-pinned Python ontology clients

- Status: accepted
- Date: 2026-08-27
- Owners: @Sannrox
- Discussion: https://github.com/Sannrox/sekai-chisei/discussions/773
- Issue: https://github.com/Sannrox/sekai-chisei/issues/698
- Supersedes: none
- Superseded by: none
- Related: [ADR 0033](0033-revision-pinned-typescript-ontology-clients.md),
  [ADR 0016](0016-versioned-rust-core-loop-client.md),
  [ADR 0019](0019-dual-capability-catalogs.md),
  [ADR 0024](0024-governed-definition-branches.md),
  [ADR 0027](0027-explicit-property-grants.md)

## Context

ADR 0033 ships a revision-pinned TypeScript projection of selected object,
link, action, and function members. Integrators also need the same contract
in Python. A second selection model, treating generation as a grant, or
embedding credentials would let names, types, errors, and scopes drift and
skip live reauthorization.

## Decision

A generated Python ontology client is the same revision-pinned projection as
the TypeScript client, in a second language. It is not authority.

Generation binds one published `sekai.definition-revision/v1` digest and an
explicit set of object, link, action, and function identities. The Python
package embeds that digest, the selected names, credential-free TypedDicts,
and invocation stubs. Live native gRPC invocation rechecks namespace, ACL,
markings, property grants, and the current published digest.

Shared selection, scope, and error contracts stay identical to TypeScript.
Empty selection, unknown members, stale revision pins, tampered package
identity, unsupported protocols, and selections that exceed an explicit
envelope fail closed without disclosing other catalog members. Releases are
superseded, never silently replaced. Discovery and generation are not grants.

Python package identity is language-specific so a TypeScript digest cannot
verify a Python payload. Property keys that are not Python identifiers stay
on the wire through the functional `TypedDict` form. PostgreSQL and SQLite
share the same published-revision input; this decision adds no storage schema.

## Alternatives considered

A Python-only selection contract would drift from TypeScript. Treating
generation as a grant would skip live reauthorization. Embedding credentials
or mixing the HTTP provider-profile matrix into the native client would
collapse two authority planes.

## Consequences

Hosts keep credentials outside the generated module and rebind the live
revision before invoke. Capability codegen remains the method-catalog
surface. The existing hand-written Python SDK facade is unchanged.

## Validation

Pure tests cover golden Python output, TypeScript scope parity, scoped
invocation, stale pins, excessive scope, hidden members, unpublished
revisions, original property keys, reserved names, and tampered package
identity against a trusted digest. The golden fixture compiles with
`python3 -m py_compile` when Python is available.
