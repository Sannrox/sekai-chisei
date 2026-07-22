# Tenant isolation conformance

`enterprise_conformance` exports the versioned
`sekai.tenant-isolation-conformance/v1` fixture, registry, and runner used to
test enterprise compositions. It does not add a tenant runtime to the community
binary.

An enterprise distribution registers every tenant-aware gRPC method and
gateway route as a `Surface`. `CaseRegistry` generates every credential and
cross-tenant profile for every registered surface; implementations cannot
hand-pick a smaller matrix. Each declaration explicitly states whether a valid
human and valid machine caller is allowed or permission-denied, keeping
authentication separate from role/scope authorization. The target adapter executes each case against the
real composition and returns an `Observation` containing the outcome and every
caller-visible body, list, count, report, receipt, metric-label, cache-key, and
error value. It also reports semantic leakage signals for behavior marker
matching cannot prove, including aggregate contamination and cross-tenant cache
reuse.

Before and after every case, the runner obtains an `IsolationSnapshot` through
an administrative fixture path independent of the request surface. Tenant B's
protected-state digest must never change. Refused, unauthenticated, and
non-disclosing not-found cases must leave both tenant digests unchanged. The
snapshot excludes audit and telemetry records that may legitimately record a
refusal.

The runner requires:

- valid human and machine credentials to remain inside tenant A;
- caller-forged tenant metadata to have no authority-bearing effect for either
  human or machine credentials;
- missing and forged credentials to be unauthenticated;
- expired or revoked credentials, revoked membership, and suspended tenants to
  fail closed;
- cross-tenant identifiers to use the non-disclosing not-found posture; and
- no tenant B identifier or value to appear in any observation channel.

Private PostgreSQL and OIDC/OAuth test targets implement `ConformanceTarget`
and run the same generated cases with `TenantFixture::deterministic()`. Adding a
tenant-aware route requires adding its `Surface` declaration. Surfaces declare
whether a cross-tenant identifier is a meaningful input; all surfaces still
receive the cross-tenant authenticated-context profile. CI passes an
independently discovered route inventory to `CaseRegistry::validate_coverage`
and asserts the generated case count from `CaseRegistry::cases()`; identifier
profiles add one case only to declarations that accept such an input.

The separate `validate_community_surface` negative profile accepts the installed
gRPC method names, gateway routes, configuration keys, and accepted
authority-bearing metadata keys of a
community composition. It rejects tenant, membership, ownership, OAuth/OIDC,
session, token, revocation, and tenant-metadata runtime surfaces.
