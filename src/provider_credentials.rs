//! Tenant-scoped model-provider credential resolver contract (#118).
//!
//! Community runtime: process-wide environment credentials when no tenant
//! context is present. Enterprise distributions implement
//! [`TenantProviderCredentialResolver`] (typically via
//! [`crate::enterprise::EnterpriseExtension`]) so each authenticated tenant
//! supplies isolated provider secrets. Callers never select tenant identity;
//! they pass only the already-authenticated context.
//!
//! Secret plaintext is never logged, serialized, or Debug-printed.

use std::collections::HashMap;
use std::fmt;
use std::sync::RwLock;

use crate::enterprise::{AuthenticatedContext, ExtensionError, SecretValue, TenantContext};

/// Contract version for tenant provider-credential resolution.
pub const PROVIDER_CREDENTIAL_RESOLVER_VERSION: &str = "sekai.provider-credential-resolver/v1";

/// Documented maximum process-local cache age for same-generation snapshots
/// (milliseconds). Generation bumps invalidate immediately.
pub const PROVIDER_CREDENTIAL_CACHE_MAX_STALE_MS: i64 = 5_000;

/// Opaque reference returned by enterprise enrollment (never the secret).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProviderCredentialRef {
    pub credential_id: String,
    pub tenant_id: String,
    pub provider: String,
    /// Monotonic generation; rotation increments it.
    pub generation: u64,
    pub status: ProviderCredentialStatus,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProviderCredentialStatus {
    Active,
    Rotated,
    Revoked,
}

impl ProviderCredentialStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Active => "active",
            Self::Rotated => "rotated",
            Self::Revoked => "revoked",
        }
    }
}

/// Resolved secret material for one provider call. Debug is always redacted.
#[derive(Clone, PartialEq, Eq)]
pub struct ResolvedProviderCredential {
    pub credential_id: String,
    pub tenant_id: Option<String>,
    pub provider: String,
    pub generation: u64,
    pub secret: SecretValue,
}

impl fmt::Debug for ResolvedProviderCredential {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ResolvedProviderCredential")
            .field("credential_id", &self.credential_id)
            .field("tenant_id", &self.tenant_id)
            .field("provider", &self.provider)
            .field("generation", &self.generation)
            .field("secret", &"[REDACTED]")
            .finish()
    }
}

/// Backend-neutral resolution boundary.
///
/// Implementations must:
/// - derive tenant only from authenticated context (never request parameters);
/// - fail closed without leaking whether a secret exists for another tenant;
/// - never place secret material in logs, audit, receipts, or metrics.
pub trait TenantProviderCredentialResolver: Send + Sync {
    fn contract_version(&self) -> &'static str {
        PROVIDER_CREDENTIAL_RESOLVER_VERSION
    }

    /// Resolve an active credential for `provider` under the authenticated tenant.
    fn resolve(
        &self,
        context: &AuthenticatedContext,
        provider: &str,
    ) -> Result<ResolvedProviderCredential, ExtensionError>;
}

/// Fail-closed community resolver: process-wide environment credentials only
/// when the caller has **no** tenant binding. Tenant-scoped requests without an
/// enterprise resolver fail closed.
pub struct ProcessEnvProviderCredentialResolver;

impl TenantProviderCredentialResolver for ProcessEnvProviderCredentialResolver {
    fn resolve(
        &self,
        context: &AuthenticatedContext,
        provider: &str,
    ) -> Result<ResolvedProviderCredential, ExtensionError> {
        if context.tenant.is_some() {
            // Community binary never invents tenant-scoped provider secrets.
            return Err(ExtensionError::Unavailable(
                "tenant-scoped provider credentials require an enterprise resolver".into(),
            ));
        }
        let env_name = env_name_for_provider(provider).ok_or(ExtensionError::CredentialNotFound)?;
        let value = std::env::var(env_name).map_err(|_| ExtensionError::CredentialNotFound)?;
        if value.trim().is_empty() {
            return Err(ExtensionError::CredentialNotFound);
        }
        Ok(ResolvedProviderCredential {
            credential_id: format!("env:{env_name}"),
            tenant_id: None,
            provider: provider.to_string(),
            generation: 1,
            secret: SecretValue::new(value),
        })
    }
}

fn env_name_for_provider(provider: &str) -> Option<&'static str> {
    match provider {
        "openai" => Some("OPENAI_API_KEY"),
        "anthropic" => Some("ANTHROPIC_API_KEY"),
        "xai" => Some("XAI_API_KEY"),
        _ => None,
    }
}

/// In-memory enterprise fake for tests and local fakes.
///
/// Stores secrets only in process memory; never serializes them.
#[derive(Default)]
pub struct MemoryTenantProviderCredentialResolver {
    // (tenant_id, provider) -> active credential
    active: RwLock<HashMap<(String, String), ResolvedProviderCredential>>,
}

impl MemoryTenantProviderCredentialResolver {
    pub fn new() -> Self {
        Self::default()
    }

    /// Install or replace the active credential for one tenant+provider.
    /// Rotation increments generation; plaintext is not returned.
    pub fn upsert(
        &self,
        tenant_id: &str,
        provider: &str,
        secret: impl Into<String>,
    ) -> ProviderCredentialRef {
        let secret = secret.into();
        let mut map = self.active.write().unwrap();
        let key = (tenant_id.to_string(), provider.to_string());
        let generation = map
            .get(&key)
            .map(|c| c.generation.saturating_add(1))
            .unwrap_or(1);
        let credential_id = format!("mem:{tenant_id}:{provider}:g{generation}");
        map.insert(
            key,
            ResolvedProviderCredential {
                credential_id: credential_id.clone(),
                tenant_id: Some(tenant_id.to_string()),
                provider: provider.to_string(),
                generation,
                secret: SecretValue::new(secret),
            },
        );
        ProviderCredentialRef {
            credential_id,
            tenant_id: tenant_id.to_string(),
            provider: provider.to_string(),
            generation,
            status: ProviderCredentialStatus::Active,
        }
    }

    pub fn revoke(&self, tenant_id: &str, provider: &str) {
        self.active
            .write()
            .unwrap()
            .remove(&(tenant_id.to_string(), provider.to_string()));
    }
}

impl TenantProviderCredentialResolver for MemoryTenantProviderCredentialResolver {
    fn resolve(
        &self,
        context: &AuthenticatedContext,
        provider: &str,
    ) -> Result<ResolvedProviderCredential, ExtensionError> {
        let tenant = context
            .tenant
            .as_ref()
            .ok_or(ExtensionError::Unauthenticated)?;
        self.active
            .read()
            .unwrap()
            .get(&(tenant.tenant_id.clone(), provider.to_string()))
            .cloned()
            .ok_or(ExtensionError::CredentialNotFound)
    }
}

/// Resolve using an optional enterprise/memory resolver, falling back to env
/// only for unscoped (community) callers.
pub fn resolve_provider_credential(
    resolver: Option<&dyn TenantProviderCredentialResolver>,
    context: &AuthenticatedContext,
    provider: &str,
) -> Result<ResolvedProviderCredential, ExtensionError> {
    if provider.trim().is_empty() {
        return Err(ExtensionError::CredentialNotFound);
    }
    if let Some(resolver) = resolver {
        return resolver.resolve(context, provider);
    }
    ProcessEnvProviderCredentialResolver.resolve(context, provider)
}

/// Build a machine context for community/process-wide resolution tests.
pub fn community_machine_context(subject: &str) -> AuthenticatedContext {
    AuthenticatedContext::machine(crate::enterprise::AuthenticatedPrincipal {
        subject: subject.into(),
        credential_id: format!("machine:{subject}"),
    })
}

/// Build a tenant-bound context for enterprise resolver tests.
pub fn tenant_context(tenant_id: &str, subject: &str) -> AuthenticatedContext {
    let mut ctx = AuthenticatedContext::machine(crate::enterprise::AuthenticatedPrincipal {
        subject: subject.into(),
        credential_id: format!("tenant-cred:{tenant_id}:{subject}"),
    });
    ctx.tenant = Some(TenantContext {
        tenant_id: tenant_id.into(),
        subject: subject.into(),
    });
    ctx.issuer = "https://issuer.test".into();
    ctx.resource = "https://sekai.test".into();
    ctx
}

/// Fail closed helper used by gateway/Chisei when resolution fails.
/// Returns a non-disclosing message (no tenant/provider existence leak).
pub fn resolution_failure_message(error: &ExtensionError) -> &'static str {
    match error {
        ExtensionError::CredentialNotFound
        | ExtensionError::Unauthenticated
        | ExtensionError::PermissionDenied
        | ExtensionError::Revoked
        | ExtensionError::MembershipRevoked
        | ExtensionError::TenantSuspended
        | ExtensionError::Expired => "provider credential unavailable",
        ExtensionError::Unavailable(_) => "provider credential resolver unavailable",
        _ => "provider credential resolution failed",
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn two_tenants_share_provider_name_with_isolated_secrets() {
        let store = MemoryTenantProviderCredentialResolver::new();
        store.upsert("tenant-a", "openai", "sk-a");
        store.upsert("tenant-b", "openai", "sk-b");

        let a = store
            .resolve(&tenant_context("tenant-a", "alice"), "openai")
            .unwrap();
        let b = store
            .resolve(&tenant_context("tenant-b", "bob"), "openai")
            .unwrap();
        assert_eq!(a.secret.expose(), "sk-a");
        assert_eq!(b.secret.expose(), "sk-b");
        assert_ne!(a.credential_id, b.credential_id);
        assert_eq!(a.tenant_id.as_deref(), Some("tenant-a"));
        assert_eq!(b.tenant_id.as_deref(), Some("tenant-b"));
    }

    #[test]
    fn rotation_bumps_generation_and_revocation_fails_closed() {
        let store = MemoryTenantProviderCredentialResolver::new();
        let first = store.upsert("tenant-a", "openai", "sk-old");
        assert_eq!(first.generation, 1);
        let second = store.upsert("tenant-a", "openai", "sk-new");
        assert_eq!(second.generation, 2);
        let resolved = store
            .resolve(&tenant_context("tenant-a", "alice"), "openai")
            .unwrap();
        assert_eq!(resolved.generation, 2);
        assert_eq!(resolved.secret.expose(), "sk-new");

        store.revoke("tenant-a", "openai");
        let err = store
            .resolve(&tenant_context("tenant-a", "alice"), "openai")
            .unwrap_err();
        assert!(matches!(err, ExtensionError::CredentialNotFound));
        // Failure message does not embed tenant id or secret material.
        let msg = resolution_failure_message(&err);
        assert!(!msg.contains("tenant-a"));
        assert!(!msg.contains("sk-"));
    }

    #[test]
    fn community_env_resolver_rejects_tenant_scoped_requests() {
        let resolver = ProcessEnvProviderCredentialResolver;
        let err = resolver
            .resolve(&tenant_context("tenant-a", "alice"), "openai")
            .unwrap_err();
        assert!(matches!(err, ExtensionError::Unavailable(_)));
    }

    #[test]
    fn resolve_helper_uses_injected_resolver() {
        let store = MemoryTenantProviderCredentialResolver::new();
        store.upsert("tenant-a", "anthropic", "ant-secret");
        let resolved = resolve_provider_credential(
            Some(&store),
            &tenant_context("tenant-a", "alice"),
            "anthropic",
        )
        .unwrap();
        assert_eq!(resolved.secret.expose(), "ant-secret");
    }

    #[test]
    fn debug_redacts_secret_material() {
        let cred = ResolvedProviderCredential {
            credential_id: "id-1".into(),
            tenant_id: Some("tenant-a".into()),
            provider: "openai".into(),
            generation: 1,
            secret: SecretValue::new("sk-super-secret"),
        };
        let rendered = format!("{cred:?}");
        assert!(rendered.contains("[REDACTED]"));
        assert!(!rendered.contains("sk-super-secret"));
    }

    #[test]
    fn missing_provider_fails_without_metadata_leak() {
        let store = MemoryTenantProviderCredentialResolver::new();
        let err = store
            .resolve(&tenant_context("tenant-a", "alice"), "openai")
            .unwrap_err();
        let msg = resolution_failure_message(&err);
        assert_eq!(msg, "provider credential unavailable");
        assert!(!msg.contains("tenant"));
        assert!(!msg.contains("sk-"));
    }
}
