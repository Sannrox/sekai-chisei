# ADR 0033: Generate revision-pinned TypeScript ontology clients

- Status: accepted
- Date: 2026-08-26
- Owners: @Sannrox
- Discussion: https://github.com/Sannrox/sekai-chisei/discussions/759
- Issue: https://github.com/Sannrox/sekai-chisei/issues/694
- Supersedes: none
- Superseded by: none
- Related: [ADR 0016](0016-versioned-rust-core-loop-client.md), [ADR 0019](0019-dual-capability-catalogs.md), [ADR 0024](0024-governed-definition-branches.md), [ADR 0027](0027-explicit-property-grants.md)

## Context

Capability codegen emits method stubs from a selected native catalog subset.
Integrators still need schema-typed object, link, action, and function
surfaces pinned to one published definition revision. Emitting the full
catalog, treating generation as a grant, or embedding credentials would
disclose hidden members and skip live reauthorization.

## Decision

A generated TypeScript ontology client is a revision-pinned projection, not
authority. Generation binds one published `sekai.definition-revision/v1`
digest and an explicit set of object, link, action, and function identities.
The package embeds that digest, the selected names, and credential-free types
plus invocation stubs. Live native gRPC invocation rechecks namespace, ACL,
markings, property grants, and the current published digest.

Empty selection, unknown members, stale revision pins, tampered package
identity, unsupported protocols, and selections that exceed an explicit
envelope fail closed without disclosing other catalog members. Releases are
superseded, never silently replaced. Discovery and generation are not grants.
Native and gateway provider catalogs stay separate.

`function` is a first-class definition member kind so callable ontology
functions share the same published revision as object, link, and action
types.

## Alternatives considered

Emitting every unpublished member as TypeScript would disclose hidden types.
Treating generation as a grant would skip live reauthorization. Mixing the
HTTP provider-profile matrix into the native client would collapse two
authority planes.

## Consequences

Hosts keep credentials outside the generated package and rebind the live
revision before invoke. Capability codegen remains the method-catalog
surface. PostgreSQL and SQLite share the same published-revision input; this
decision adds no storage schema.

## Validation

Pure tests cover golden TypeScript output, scoped invocation, stale pins,
excessive scope, hidden members, unpublished revisions, original property
keys, and tampered package identity against a trusted digest. The golden
fixture typechecks with `tsc` when it is available.
