# Tenant-scoped provider credential resolver (#118)

Backend-neutral contract for resolving **model-provider** API credentials.
Enrollment, encryption-at-rest, rotation, and tenant administration remain
enterprise-owned. The community runtime does not store tenant provider secrets.

Hosted Aldunis supplies **one process key per Chisei instance**
(`OPENAI_API_KEY`, `ANTHROPIC_API_KEY`, or `XAI_API_KEY`). Customers do not
paste keys. A tenant-specific enterprise row still wins when one exists.

## Contract

| Piece | Location |
| --- | --- |
| Version | `sekai.provider-credential-resolver/v1` |
| Types | `src/provider_credentials.rs` |
| Enterprise hook | `EnterpriseExtension::resolve_provider_credential` |
| Instance key | `ProcessEnvProviderCredentialResolver` (process env; tenant ignored) |
| Deterministic fake | `MemoryTenantProviderCredentialResolver` |

Resolution input is always an [`AuthenticatedContext`](enterprise-identity-extension.md)
plus a provider id (`openai`, `anthropic`, `xai`, …). Callers **must not** pass
caller-selected tenant ids.

## Behavior

- **Two tenants, same provider name** → isolated secrets when enterprise rows
  exist (see memory-resolver tests).
- **Rotation** → generation increments; active resolve returns the new secret.
- **Revocation / missing tenant row** → fall back to the instance process key.
  Auth failures (`Unauthenticated`, forged-tenant mismatch) do not fall back.
- **Instance env key** → `tenant_id` is `None`; `credential_id` is
  `env:OPENAI_API_KEY` (or the matching env name). Any authenticated caller may
  use it.
- **Secrets** → `SecretValue` / `ResolvedProviderCredential` Debug is redacted;
  never place secrets in receipts, audit, logs, metrics, or exports.

## Replica bound

Enterprise implementations must invalidate process-local caches within the same
documented bound as principal credentials (`PROVIDER_CREDENTIAL_CACHE_MAX_STALE_MS`,
5s for same-generation snapshots) and immediately on generation bump. Community
env resolution is process-local by definition.

## Gateway / Chisei consumption

`PlanExecution` and `ExecutePlanStream` carry the trusted
authenticated context through the native Chisei path. After policy selects the
provider, Chisei asks the enterprise extension (when present) and then the
instance env key. An enterprise secret wins. `CredentialNotFound` or a
community binary without an extension uses the process key. A tenant-scoped
enterprise secret must match the authenticated tenant; an instance key
(`tenant_id: None`) is accepted for any caller.

Resolution happens before budget reservation. Failure remains non-disclosing.

## Non-goals

- Tenant admin RPCs for credential enrollment (enterprise authority).
- Provider billing / invoice state.
- Storing secrets in community SQLite.
- Customer-facing BYOK. The instance key is operator-owned.
