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
