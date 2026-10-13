# Tenant-scoped provider credential resolver (#118)

Backend-neutral contract for resolving **model-provider** API credentials.
Enrollment, encryption-at-rest, rotation, and tenant administration remain
enterprise-owned. The community runtime does not store tenant provider secrets.

A deployment may supply **one process key per Chisei instance**
(`OPENAI_API_KEY`, `ANTHROPIC_API_KEY`, or `XAI_API_KEY`). Without an
enterprise extension every caller uses it. With an extension installed, the
extension decides: it returns a tenant row, or the instance key explicitly
through `ProcessEnvProviderCredentialResolver`, or refuses.

## Contract

| Piece | Location |
| --- | --- |
| Version | `sekai.provider-credential-resolver/v1` |
| Types | `src/provider_credentials.rs` |
| Enterprise hooks | `EnterpriseExtension::admit_model`, then `EnterpriseExtension::resolve_provider_credential` |
| Instance key | `ProcessEnvProviderCredentialResolver` (process env; tenant ignored) |
| Deterministic fake | `MemoryTenantProviderCredentialResolver` |

Resolution input is always an [`AuthenticatedContext`](enterprise-identity-extension.md)
plus a provider id (`openai`, `anthropic`, `xai`, …). Callers **must not** pass
caller-selected tenant ids.

## Model admission (#1352)

Before a provider execution's credential lookup, and for keyless providers
too, Chisei passes the resolved `ModelIdentity` to
`EnterpriseExtension::admit_model`: provider,
canonical and upstream model, profile version, the pinned `artifact_digest`
when the route carries one (a hosted endpoint's `artifact_digest`; registered
hosted routes do not pin one yet), and the endpoint base URL that will receive the
prompt (the same value the provider client is built with). The default admits.
`PermissionDenied` refuses with `PERMISSION_DENIED` ("model not admitted") and
`Unavailable` with `UNAVAILABLE`; no provider call is made either way.
Operator-configured internal models (leak reviewer, scoring, evaluation) are
not tenant routes and are not admitted through this hook.

Durable review state for that identity is stored per namespace (#1493). The
empty namespace is the instance default; a named namespace may override it.
Route admission (#1494) refuses a model that is not `enabled` for the
namespace, identity, and residency region before this hook runs, and records
the refusal on the decision ledger. `admit_model` remains an additional
enterprise gate.

## Behavior

- **Two tenants, same provider name** → isolated secrets when enterprise rows
  exist (see memory-resolver tests).
- **Rotation** → generation increments; active resolve returns the new secret.
- **Any extension error**, `CredentialNotFound` included → execution is
  refused. There is no fallback to the process key while an extension is
  installed; an extension that wants the instance key returns it.
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
provider, Chisei asks the enterprise extension to admit the model and then for
the credential. Only a community binary without an extension uses the process
key directly. A tenant-scoped
enterprise secret must match the authenticated tenant; an instance key
(`tenant_id: None`) is accepted for any caller.

Resolution happens before budget reservation. Failure remains non-disclosing.

## Non-goals

- Tenant admin RPCs for credential enrollment (enterprise authority).
- Provider billing / invoice state.
- Storing secrets in community SQLite.
- Customer-facing BYOK. The instance key is operator-owned.
