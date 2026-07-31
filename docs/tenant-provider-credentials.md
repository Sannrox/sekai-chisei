# Tenant-scoped provider credential resolver (#118)

Backend-neutral contract for resolving **model-provider** API credentials under
an authenticated tenant. Enrollment, encryption-at-rest, rotation workflows, and
tenant administration remain enterprise-owned. The community runtime does not
store tenant provider secrets.

## Contract

| Piece | Location |
| --- | --- |
| Version | `sekai.provider-credential-resolver/v1` |
| Types | `src/provider_credentials.rs` |
| Enterprise hook | `EnterpriseExtension::resolve_provider_credential` |
| Community fallback | `ProcessEnvProviderCredentialResolver` (process env only, unscoped) |
| Deterministic fake | `MemoryTenantProviderCredentialResolver` |

Resolution input is always an [`AuthenticatedContext`](enterprise-identity-extension.md)
plus a provider id (`openai`, `anthropic`, `xai`, …). Callers **must not** pass
caller-selected tenant ids.

## Behavior

- **Two tenants, same provider name** → isolated secrets (see memory-resolver tests).
- **Rotation** → generation increments; active resolve returns the new secret.
- **Revocation / missing** → fail closed with a non-disclosing error string
  (`provider credential unavailable`); no existence leak across tenants.
- **Tenant-scoped request on community binary without enterprise resolver** →
  `Unavailable` (does not invent per-tenant secrets from env).
- **Unscoped community callers** → `OPENAI_API_KEY` / `ANTHROPIC_API_KEY` /
  `XAI_API_KEY` via process environment.
- **Secrets** → `SecretValue` / `ResolvedProviderCredential` Debug is redacted;
  never place secrets in receipts, audit, logs, metrics, or exports.

## Replica bound

Enterprise implementations must invalidate process-local caches within the same
documented bound as principal credentials (`PROVIDER_CREDENTIAL_CACHE_MAX_STALE_MS`,
5s for same-generation snapshots) and immediately on generation bump. Community
env resolution is process-local by definition.

## Gateway / Chisei consumption

`PlanExecution`, `ExecutePlan`, and `ExecutePlanStream` carry the trusted
authenticated context through the native Chisei path. For tenant-scoped
execution, Chisei resolves the provider credential from the enterprise
extension after policy selects the provider and immediately before constructing
the LLM adapter. Credential resolution happens before budget reservation and
failure is non-disclosing.

An unscoped enterprise context also resolves through its extension and requires
an unscoped returned credential; it does not inherit community process keys.

Unscoped community launches continue to use process-wide configuration or
environment keys. A tenant-scoped request without an enterprise extension
fails closed rather than falling back to a process key.

## Non-goals

- Tenant admin RPCs for credential enrollment (enterprise authority).
- Provider billing / invoice state.
- Storing secrets in community SQLite.
