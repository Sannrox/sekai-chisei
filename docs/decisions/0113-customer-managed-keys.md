# ADR 0113: Customer-managed keys use envelope encryption and one key-provider contract

- Status: accepted (effective on merge)
- Date: 2026-10-18
- Owners: @Sannrox
- Source: [Issue #1577](https://github.com/Sannrox/sekai-chisei/issues/1577)
- Supersedes: none
- Superseded by: none
- Related: [ADR 0025](0025-storage-enforced-object-security.md),
  [ADR 0032](0032-hierarchical-classifications.md),
  [ADR 0099](0099-shared-identity-and-tenancy.md)

## Context

Data at rest is protected only by host and volume controls. Markings decide who
may read a fact; they do not bind ciphertext to a customer-held key. A customer
cannot revoke access by revoking a key, or prove which key protects which
tenant. Each store would otherwise invent its own wrapping scheme.

This record is the contract. Per-store encryption, provider adapters, and
on-disk format changes remain the linked follow-up issues. Rollout is staged
per store behind a profile flag.

## Decision

### Hierarchy

A customer root key (KEK) lives in the customer's key provider. The KEK wraps
per-tenant data keys (DEKs). A store may further scope a DEK to a namespace or
marking; that scope is recorded on the wrapped DEK and checked on unwrap.
Plaintext DEKs exist only in process memory and expire from cache after a
bounded lifetime. The KEK never leaves the provider. Engines never receive it.

`tenant_id` is the isolation key on every wrap and unwrap, matching ADR 0099.
A missing tenant denies. Markings remain an authorization layer; they do not
replace the key.

### Key-provider trait

Every adapter implements wrap, unwrap, KEK rotate, describe, and revoke.
KEK rotate installs a new current KEK and retains the previous KEK during
overlap so existing wrapped DEKs still unwrap. Describe returns provider kind,
key ids, and algorithm names. It never returns key material.

Admitted production kinds: KMIP, PKCS#11 HSM, and cloud KMS APIs. A file-based
or in-memory provider is a development aid and is refused in production
profiles.

### Delivery to engines

Chisei or the deployer hands an engine wrapped DEKs plus an unwrap grant
scoped to tenant, purpose, and lifetime. The engine unwraps through the
provider. Unwrap past grant expiry, for the wrong tenant or purpose, or after
revocation, fails closed. The engine encrypts and decrypts its own bytes with
the DEK; it does not call the KEK.

### Rotation

KEK rotation installs a new current KEK and keeps the previous KEK during
overlap. Store data is not rewritten. Existing envelopes unwrap with the
previous KEK until stores rewrap them under the new current KEK. Completing
rotation drops the previous KEK. A second KEK rotation while overlap is active
fails closed. DEK rotation mints a new DEK, records the old and new ids, and
re-encrypts on compaction or rewrite. Both rotations are auditable.

### Revocation and crypto-shredding

Revoking a KEK or a tenant DEK makes wrapped data unreadable. Services return
a clear revoked state and refuse partial reads. Restoring a revoked key is a
separate, audited ceremony; it is not implicit on restart.

### Audit

Every unwrap emits an audit event with tenant, engine, purpose, and key id.
Audit rows never contain key material, wrapped blobs, or DEK bytes.

### Scope

Covered by this contract and a linked follow-up:

| Store | Follow-up |
| --- | --- |
| Mizuchi tables and spills | [Sannrox/mizuchi#143](https://github.com/Sannrox/mizuchi/issues/143) |
| Kako workspaces and outputs | [Sannrox/kako#50](https://github.com/Sannrox/kako/issues/50) |
| Ezu WAL and snapshots | [Sannrox/ezu#11](https://github.com/Sannrox/ezu/issues/11) |
| Mikura object log | [Sannrox/mikura#282](https://github.com/Sannrox/mikura/issues/282) |
| Dark-site key provider and ceremony | [Sannrox/tenkai#649](https://github.com/Sannrox/tenkai/issues/649) |
| Connector credentials and buffers | [Sannrox/hashi#12](https://github.com/Sannrox/hashi/issues/12) |
| Field-device local store | device-bound key; follow-up on the field client |

Not covered yet: the time-series store and PostgreSQL cluster volumes, which
remain host- or volume-encrypted until a later issue binds them to this
hierarchy. Caches and spills of covered stores are in scope for that store's
follow-up. Exports must be re-encrypted under an export-purpose DEK or
refused.

### Conformance

`sekai-keys` is the shared contract crate. Every store adapter runs
`sekai_keys::conformance::assert_provider_contract`: a revoked key yields no
reads, KEK rotation loses no plaintext, and Debug/audit contain no plaintext
key.

## Alternatives considered

Per-store wrapping schemes drift and cannot share a customer KEK. Application-
layer encryption after a successful store read leaves spills, caches, and
backups in plaintext. Host-volume encryption alone cannot crypto-shred one
tenant or prove which key wrapped which DEK.

## Consequences

Stores take a wrapped DEK and an unwrap grant; they do not grow a second key
hierarchy. Production profiles fail closed without an admitted provider kind.
Follow-up issues change on-disk formats (GATE:mig on those slices). This
record does not encrypt existing community data.

## Validation

`sekai-keys` unit and conformance tests cover wrap/unwrap, grant mismatch,
revocation, KEK rewrap without data rewrite, production refusal of file and
memory providers, and redacted Debug. Per-store slices add their own
compaction and rewrite evidence.
