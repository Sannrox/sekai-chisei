# ADR 0099: Shared identity and tenancy contract

- Status: accepted (effective on merge)
- Date: 2026-10-10
- Owners: @Sannrox
- Source: [Issue #1397](https://github.com/Sannrox/sekai-chisei/issues/1397)
- Supersedes: none
- Superseded by: none
- Related: [ADR 0088](0088-one-object-log-host-many-clerk-clients.md),
  [ADR 0091](0091-object-log-owns-evaluate-identity.md)

## Context

Callers currently reach services through several credential formats and
namespace-based authorization paths. The identity-extension context carries an
optional tenant and distinguishes human sessions from machine credentials, but
has no space role or delegating actor. A request namespace is not proof of tenant
membership. Treating a static credential, a user session, and delegated work as
interchangeable authority loses both isolation and attribution.

This proposal defines the target contract. It does not claim that existing
community credentials, storage keys, or extensions already implement it.
The accountable maintainer must approve the contract before dependent changes
adopt it. This slice records the decision; publishing the contract crate and
changing service behavior remain separate implementation obligations of #1397.

## Decision

### Isolation and permission scope

`tenant_id` is the hard isolation boundary. A namespace belongs to exactly one
tenant. Storage, cache, queue, idempotency, and lookup identities include
`(tenant_id, namespace)` wherever namespace data is addressed. An authenticated
tenant is never inferred from an untrusted request field, a default namespace,
or a shared bearer credential.

A space is a permission scope, not a storage key. Its role constrains access
within the authenticated tenant; a role does not move a namespace between
tenants. Request selectors must match authenticated authority and the current
namespace-to-tenant binding before any read, mutation, or work admission.
Absent or empty tenant authority denies tenant-scoped operations.

### Principal kinds

| Kind | Meaning | Authority constraint |
| --- | --- | --- |
| `human` | An authenticated person | Current tenant membership and product permissions |
| `service` | An application acting as itself | Explicit tenant binding and application grants; never user identity |
| `runtime` | Short-lived delegated execution | Bounded task authority and a valid delegating principal |
| `operator` | Explicit exceptional administration | Narrow capability, explicit target tenant, and durable audit |

Credential format is not principal kind. Exchanging a token cannot turn a
service into a human. A runtime retains its own subject and its delegating
actor; receipts record both. Operator authority is never derived merely from
a special namespace, a missing tenant, or a service credential.

### Signed claim contract

Use EdDSA-signed JWTs with issuer keys distributed through JWKS. A verifier
pins trusted issuers, the allowed signing algorithm, and its exact audience;
a token-supplied key location does not select trust. Unknown keys, invalid
signatures, unsupported claim versions or kinds, and invalid expiry deny access.
Key refresh is bounded and does not make verification fail open.

| Claim | Meaning and validation |
| --- | --- |
| `iss` | Trusted issuer; exact configured match |
| `aud` | The receiving service's audience; no generic stack-wide audience |
| `sub` | Non-empty stable subject of the authenticated principal |
| `kind` | Exactly one of the four principal kinds above |
| `tenant_id` | Non-empty canonical tenant identifier; required for tenant-scoped authority |
| `namespace` | Optional narrowing to one namespace owned by that tenant |
| `space` | Optional tenant-local permission scope |
| `space_role` | Optional role within `space`; invalid without that space |
| `scopes` | Explicit capabilities; absence means no granted capabilities |
| `act` | Delegating actor for runtime authority, distinct from `sub` |
| `exp` | Finite expiry; reject at or after expiry with a bounded clock tolerance |
| `jti` | Non-empty token identifier for revocation and audit correlation |

The wire profile must version the claim contract explicitly before publication.
Audience, lifetime bounds, permitted roles and delegation depth belong to that
versioned profile; they are not guessed by individual consumers. Tenant
membership, tenant status, revocation, namespace ownership and applicable
permissions are checked at the authorization boundary even for a valid
signature. A role or scope string is not independently authoritative.

### Exchange and delegated execution

A downstream call exchanges inbound authority for a token naming the receiving
service. The exchange validates the inbound token and current authority first.
Its result has no greater lifetime, scopes, tenant or namespace authority than
the inbound token and the caller's current grants. Requested restrictions may
narrow authority; they may not select another tenant or invent membership.

The exchange preserves the originating actor and the authenticated service
subject. Runtime delegation requires an explicit delegating actor; cycles,
unbounded delegation and an unsupported actor chain deny exchange. A service
may execute with its own grants, but cannot acquire human identity by supplying
an actor field. Each audience change requires a new signed token, not editing
claims locally or forwarding a broader bearer token.

A worker receives a short-lived runtime token in the authorized claim response,
bound to the claimed task, tenant, namespace and execution capabilities.
It does not receive a shared static secret. Claim and apply revalidate the
delegating principal and required current grants. Revocation between planning,
claim and apply must prevent execution; durable receipts retain subject, actor,
tenant and token identifiers without retaining raw tokens.

### Decision points

| Boundary | Owns the decision | Required enforcement |
| --- | --- | --- |
| Platform | Membership, space roles and product access | Bind current membership and product grants to issued authority |
| Chisei | Data policy, purpose, markings and governed action authorization | Evaluate authenticated tenant and delegated authority against current policy |
| Delivery plane | Delivery capabilities, signed plans and execution admission | Bind approved work to authenticated tenant and permitted capabilities |
| Store | Tenant-qualified data access | Enforce tenant and namespace identity plus supplied policy restrictions |
| Worker | Claimed execution | Verify task-bound runtime authority and fail closed without tenant or valid delegation |

The token verifier establishes authenticated claims; it does not replace any
of these decisions. An operator action must name its target tenant and produce
an audit record coupled to the authorized action. Audit failure denies actions
that require audit. No namespace bypass is part of this contract.

### Distribution and conformance

Publish one versioned contract crate containing claim types, the JWKS verifier
and reusable conformance fixtures. Issuance and product membership remain with
their owners; the crate does not become an identity server or duplicate policy.
Consumers use the same verification rules and run the fixtures at their actual
HTTP, gRPC, store or claim boundary, including:

- missing or empty tenant, wrong issuer/audience, invalid signature and expiry;
- unknown principal kind, service presented as human, and forged actor;
- cross-tenant namespace and cross-space access;
- widening exchange, revoked delegation, and revocation before claim/apply;
- absent task-bound worker authority and audit-required action without audit.

These are implementation acceptance obligations, not tests supplied by this
ADR. A conformance success must identify the crate version and consumer
boundary tested.

## Alternatives considered

- Keep credential formats and tenant claim names per service. This preserves
  local compatibility but repeats verification, weakens exchange semantics,
  and makes cross-service isolation difficult to prove.
- Use namespace or space as the isolation key. Namespaces are tenant-owned
  resources and spaces are permissions; neither substitutes for tenant identity.
- Put all authorization in the token verifier. Current data policy, product
  membership and delivery admission have different owners and lifecycles.
  Sharing authentication does not require centralizing those decisions.

## Migration and compatibility

Adoption is staged and gated. Inventory existing credentials and namespace
bindings, bind each credential and namespace to an explicit tenant, and report
ambiguous rows for human resolution before enforcing the new contract. Never
backfill an unknown tenant with a shared default. Tenant-qualified storage-key
changes must preserve rows and use the owning service's migration gate.

Introduce the published verifier and exchanged tokens before withdrawing old
issuance paths. Any bounded compatibility window must be explicit, auditable,
and restricted to a known tenant binding. It cannot permit tenant-less access
to tenant-scoped data. Extension context changes require explicit contract
versioning and consumer compatibility checks, even when wire fields are
additive. Existing field numbers must never change.

Static standalone credentials remain a separate existing mode until its owner
defines adoption; they must not silently activate multi-tenant authority.
Rollback after tenant-qualified writes must preserve tenant separation and
refuse a previous format that cannot represent it. No release, migration or
credential rotation is performed by this ADR.

## Follow-up ownership and evidence

The linked implementation issues own service adoption:
[#1398](https://github.com/Sannrox/sekai-chisei/issues/1398) carries space, role and
actor; [#1400](https://github.com/Sannrox/sekai-chisei/issues/1400) rejects unbound
machine credentials; [#1401](https://github.com/Sannrox/sekai-chisei/issues/1401)
separates service identity; [#1402](https://github.com/Sannrox/sekai-chisei/issues/1402)
revalidates delegation, with worker claim enforcement after
[#1389](https://github.com/Sannrox/sekai-chisei/issues/1389).
[#1376](https://github.com/Sannrox/sekai-chisei/issues/1376) fixes existing read
checks independently; [#1399](https://github.com/Sannrox/sekai-chisei/issues/1399)
owns unmarked-object policy.

Other consumers are tracked by
[Tenkai #589](https://github.com/Sannrox/tenkai/issues/589),
[Rusui #604](https://github.com/Sannrox/rusui/issues/604),
[Shikigami #440](https://github.com/Sannrox/shikigami/issues/440),
[Kako #10](https://github.com/Sannrox/kako/issues/10), and
[Mikura #234](https://github.com/Sannrox/mikura/issues/234) /
[#235](https://github.com/Sannrox/mikura/issues/235).
Platform counterparts are tracked by their owner without private links here.

Contract acceptance, crate publication, consumer conformance, and migration
approval are separate evidence. Merging this proposal alone proves none of the
runtime or publication obligations. Accountable maintainer sign-off is required
before this record becomes accepted and dependent changes adopt it.
