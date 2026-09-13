# ADR 0070: Publish a compatibility matrix as a projection of shipped metadata

- Status: accepted
- Date: 2026-09-13
- Owners: @Sannrox
- Discussion: source Issue [#873](https://github.com/Sannrox/sekai-chisei/issues/873)
- Issue: https://github.com/Sannrox/sekai-chisei/issues/873 (#873)
- Supersedes: none
- Superseded by: none
- Related: [ADR 0051](0051-versioned-client-packages.md)

## Context

Consumers pin `sekai-client` at different git revisions and consume generated
TypeScript and Python trees as vendored copies. Nothing stated which server
version, proto revision, and client package versions were compatible, so
upgrades were a manual investigation. Later contract surfaces must reuse one
compatibility vocabulary rather than invent a second authority.

## Decision

Each release publishes `compatibility.json` (`sekai.compatibility-matrix/v1`)
as a projection of shipped Cargo, proto, and SDK metadata:

- server / `sekai-chisei` version
- proto contract revision (`sha256:` over `proto/sekai.proto` and
  `proto/chisei.proto`, same digest as client-package protocol pins)
- `sekai-proto`, `sekai-client`, TypeScript, and Python package versions
- `minimum_compatible_server`, equal to the server version that produced the
  matrix unless a later release explicitly raises it

`sekaictl admin compatibility check` reports on-matrix or off-matrix. Exact
version pins match (`=` for Cargo, `==` for Python, exact npm versions).
Cargo caret ranges are accepted only when `Cargo.lock` resolves the crate to
the matrix version from a non-git source. Git `rev` pins, git lockfile
sources, mismatched lockfile versions, and vendored TypeScript or Python
source copies are off-matrix until replaced by an on-matrix package pin. The
check names the expected on-matrix revision.
Unknown matrix contracts fail closed. The matrix does not invent
compatibility and does not upload registry bytes.

## Alternatives considered

- Treat semver-compatible ranges or git SHAs as compatible. Rejected: that
  invents a compatibility claim the proto bytes do not make.
- Keep compatibility only in prose. Rejected: CI cannot prevent drift.

## Consequences

Release attaches the generated matrix. CI regenerates it from the workspace
and fails when it diverges from `proto/` or the committed file. Later HTTP
or package-registry contracts must respect this vocabulary.

## Validation

A deterministic test regenerates the matrix from Cargo, proto, and SDK
metadata, compares it to `compatibility.json` and the proto digest, passes
two coordinated Rust consumer pins, and fails a tampered `rev` pin and the
vendored TypeScript copy while naming the expected revision.
