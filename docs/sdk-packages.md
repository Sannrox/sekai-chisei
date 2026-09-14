# Versioned client packages

Publish reproducible Rust, TypeScript, and Python clients as first-class
objects that pin protocol, source, package identity, and provenance. The plane
does not upload registry bytes or treat discovery as a grant. See
[ADR 0051](decisions/0051-versioned-client-packages.md) and
[Discussion 804](https://github.com/Sannrox/sekai-chisei/discussions/804).

## Contract

`sekai.client-package/v1` binds:

- identity `(namespace, package_id)` and owner
- language (`rust`, `typescript`, `python`)
- package name and version
- protocol digest, source digest, and package digest
- optional catalog-version pin and operation correlation
- optional predecessor identity for supersession

## Operator workflow

```text
sekaictl admin sdk-packages publish \
  --package ./package.json --protocol ./proto.txt --source ./source.txt \
  --artifact ./artifact.txt --actor integrator
sekaictl admin sdk-packages get --namespace sdk --package-id pkg:rust-0.1.0 \
  --actor integrator
sekaictl admin sdk-packages verify --namespace sdk --package-id pkg:rust-0.1.0 \
  --protocol ./proto.txt --source ./source.txt --artifact ./artifact.txt \
  --actor integrator
sekaictl admin sdk-packages smoke --namespace sdk --package-id pkg:rust-0.1.0 \
  --protocol ./proto.txt --source ./source.txt --artifact ./artifact.txt \
  --actor integrator
```

The actor must be the registered owner. Replay of the same live identity and
matching digests is idempotent. A later version of the same language and
package name supersedes the previous live publication when `predecessor_id`
names it. The superseded record stays inspectable and fails smoke.

## Failure

| Condition | Result |
| --- | --- |
| Unknown package, foreign owner, digest mismatch, unknown language, superseded smoke | `client package is unavailable` |
| Unknown contract version | `client package protocol is unsupported` |

SQLite stores publications. PostgreSQL surfaces stay unavailable.

Local artifacts, publication records, and registry packages are different
objects. Current `main` stages isolated Rust, TypeScript, and Python trees,
pins `sekai-proto` beside the Rust client, rewrites consumer fixtures onto
local copies, and re-hashes protocol (`sekai.proto` and `chisei.proto`), source,
and package bytes from disk (#840, #843, #844). It does not claim cargo, npm, or
pip registry installs, and it does not upload crates.io, npm, or PyPI bytes.

## Compatibility matrix

Each release publishes [`compatibility.json`](../compatibility.json)
(`sekai.compatibility-matrix/v1`) as a projection of the shipped server
version, proto revision, `sekai-client`, `sekai-proto`, and TypeScript/Python
package versions. Generated HTTP/JSON clients (`sdk/typescript/http.ts`,
`sdk/python/sekai_http.py`) ship in those same packages and are reproduced
from the maturity table in CI. See [ADR 0070](decisions/0070-compatibility-matrix.md).
The file is not a second authority: CI regenerates it from Cargo, proto, and
SDK metadata and fails when it drifts.

```text
sekaictl admin compatibility generate --out compatibility.json
sekaictl admin compatibility check --matrix compatibility.json --consumer ./crates/sekai-client
```

On-matrix means the consumer names those exact versions. Cargo `=` pins are
exact; a caret such as `"0.1.2"` is on-matrix only when `Cargo.lock` resolves
that crate to the matrix version from a non-git source. A git `rev` pin, a
git lockfile source, a mismatched lockfile, or a vendored TypeScript/Python
source copy is off-matrix. The check names the expected on-matrix
`sekai-client` / `sekai-proto` / proto revision.

## Upgrade cadence

1. Wait for the GitHub release of a `v*` tag. It attaches `compatibility.json`.
2. Bump `sekai-client` and `sekai-proto` together to the versions on that
   matrix. Do not advance one crate or a git `rev` without the other.
3. Replace vendored TypeScript or Python trees with a pin of
   `@sannrox/sekai-chisei-sdk` / `sekai-chisei-sdk` at the matrix version.
   Source copies stay off-matrix until that replacement.
4. Run `sekaictl admin compatibility check --matrix compatibility.json
   --consumer <path>` in consumer CI. A tampered or stale pin must fail.
5. Coordinate the bump across every public-family consumer in one change.
   The matrix does not open dependency PRs.
