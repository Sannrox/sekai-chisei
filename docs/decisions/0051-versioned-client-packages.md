# ADR 0051: Publish versioned client packages with protocol and provenance pins

- Status: accepted
- Date: 2026-08-31
- Owners: @Sannrox
- Discussion: https://github.com/Sannrox/sekai-chisei/discussions/804
- Issue: https://github.com/Sannrox/sekai-chisei/issues/702 (#702)
- Supersedes: none
- Superseded by: none
- Related: [ADR 0016](0016-versioned-rust-core-loop-client.md),
  [ADR 0033](0033-revision-pinned-typescript-ontology-clients.md),
  [ADR 0040](0040-revision-pinned-python-ontology-clients.md)

## Context

ADR 0016, ADR 0033, and ADR 0040 produce Rust, TypeScript, and Python clients.
Those trees are not yet first-class versioned objects that bind protocol,
source, package identity, and provenance. Without that object, a consumer can
install a stale or tampered client and treat discovery as a grant.

## Decision

A `sekai.client-package/v1` object is identified by `(namespace, package_id)`.
It pins language (`rust`, `typescript`, `python`), package name and version,
protocol digest, source digest, package digest, owner, optional catalog
version, and operation correlation.

The plane does not upload registry bytes, embed credentials, or authorize
invocation. Same live identity and matching digests are idempotent. The same
version with different digests fails closed. A successor version of the same
language and package name supersedes the previous live publication. The prior
record remains inspectable and is never silently rewritten.

Unknown languages, stale contracts, tampered digests, foreign owners, and
superseded packages fail as one unavailable result. SQLite is the reference
store. PostgreSQL stays unavailable.

## Alternatives considered

Publishing registry artifacts as authority was rejected because credentials and
remote failure would become truth. Generation without a publication object was
rejected because provenance would stay implicit. Mixing native and HTTP
provider catalogs was rejected because those catalogs are already separate.

## Consequences

Operators publish, retrieve, verify, and smoke Rust, TypeScript, and Python
clients through `sekaictl admin sdk-packages`. Existing generated clients
remain ADR 0016, ADR 0033, and ADR 0040.

## Validation

Deterministic fixtures cover publish, replay, smoke, digest checks, provenance,
supersession, tamper, unsupported protocol, and unknown language.
