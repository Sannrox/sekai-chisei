//! Backend-neutral contracts for composing enterprise authority into the control plane.
//!
//! The community runtime does not install an implementation and never derives
//! tenant authority from request metadata. Enterprise distributions may inject
//! an implementation while retaining one authoritative service process.

use std::fmt;

pub const IDENTITY_EXTENSION_VERSION: &str = "sekai.identity-extension/v1";
pub const AUTHORIZATION_SERVER_METADATA_VERSION: &str = "RFC8414";
pub const PROTECTED_RESOURCE_METADATA_VERSION: &str = "RFC9728";

/// A credential value that is deliberately opaque to formatting and serialization.
///
/// Extension implementations may inspect it through `expose`, but core logging,
/// audit, graph, metric, and diagnostic types cannot accidentally serialize it.
#[derive(Clone, PartialEq, Eq)]
pub struct SecretValue(String);

impl SecretValue {
    pub fn new(value: impl Into<String>) -> Self {
        Self(value.into())
    }

    pub fn expose(&self) -> &str {
        &self.0
    }
}

impl fmt::Debug for SecretValue {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("SecretValue([REDACTED])")
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CredentialKind {
    HumanSession,
    Machine,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuthenticatedPrincipal {
    pub subject: String,
    pub credential_id: String,
}

/// The only authority-bearing identity object consumed by HTTP and gRPC.
///
/// Every field is produced by a trusted credential validator. Request metadata
/// may carry routing hints, but it must never be used to construct this value.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuthenticatedContext {
    pub contract_version: &'static str,
    pub principal: AuthenticatedPrincipal,
    pub credential_kind: CredentialKind,
    pub tenant: Option<TenantContext>,
    pub scopes: Vec<String>,
    pub issuer: String,
    pub resource: String,
    pub expires_at: i64,
}

impl AuthenticatedContext {
    pub fn machine(principal: AuthenticatedPrincipal) -> Self {
        Self {
            contract_version: IDENTITY_EXTENSION_VERSION,
            principal,
            credential_kind: CredentialKind::Machine,
            tenant: None,
            scopes: Vec::new(),
            issuer: "sekai:community".into(),
            resource: "sekai:control-plane".into(),
            expires_at: i64::MAX,
        }
    }

    pub fn validate(&self, now: i64, issuer: &str, resource: &str) -> Result<(), ExtensionError> {
        if self.contract_version != IDENTITY_EXTENSION_VERSION {
            return Err(ExtensionError::UnsupportedVersion);
        }
        if self.issuer != issuer {
            return Err(ExtensionError::IssuerMismatch);
        }
        if self.resource != resource {
            return Err(ExtensionError::ResourceMismatch);
        }
        if self.expires_at <= now {
            return Err(ExtensionError::Expired);
        }
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SessionRequest {
    pub state: String,
    pub nonce: String,
    pub redirect_uri: String,
    pub issuer: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Session {
    pub id: String,
    pub state: String,
    pub nonce: String,
    pub redirect_uri: String,
    pub issuer: String,
    pub expires_at: i64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuthorizationCodeRequest {
    pub session_id: String,
    pub state: String,
    pub nonce: String,
    pub redirect_uri: String,
    pub code_challenge: String,
    pub scopes: Vec<String>,
    pub resource: String,
}

#[derive(Clone, PartialEq, Eq)]
pub struct AuthorizationCode {
    pub code: SecretValue,
    pub expires_at: i64,
}

impl fmt::Debug for AuthorizationCode {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("AuthorizationCode")
            .field("code", &"[REDACTED]")
            .field("expires_at", &self.expires_at)
            .finish()
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AccessCredentialRequest {
    pub code: SecretValue,
    pub code_verifier: SecretValue,
    pub redirect_uri: String,
    pub issuer: String,
    pub resource: String,
}

#[derive(Clone, PartialEq, Eq)]
pub struct AccessCredential {
    pub credential: SecretValue,
    pub context: AuthenticatedContext,
}

impl fmt::Debug for AccessCredential {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("AccessCredential")
            .field("credential", &"[REDACTED]")
            .field("context", &self.context)
            .finish()
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RevocationRequest {
    pub credential: SecretValue,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuthorizationServerMetadata {
    pub contract_version: &'static str,
    pub issuer: String,
    pub authorization_endpoint: String,
    pub token_endpoint: String,
    pub revocation_endpoint: String,
    pub scopes_supported: Vec<String>,
    pub code_challenge_methods_supported: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProtectedResourceMetadata {
    pub contract_version: &'static str,
    pub resource: String,
    pub authorization_servers: Vec<String>,
    pub scopes_supported: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TenantContext {
    pub tenant_id: String,
    pub subject: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NamespaceAction {
    Read,
    Write,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ExtensionError {
    CredentialNotFound,
    Unauthenticated,
    PermissionDenied,
    UnsupportedVersion,
    InvalidState,
    InvalidNonce,
    InvalidRedirectUri,
    InvalidPkce,
    IssuerMismatch,
    ResourceMismatch,
    Expired,
    Revoked,
    Replayed,
    MembershipRevoked,
    TenantSuspended,
    Unavailable(String),
}

/// Injection boundary implemented by an enterprise composition.
///
/// Implementations derive context only from an authenticated principal and
/// make the tenant/namespace decision before the core accesses durable data.
pub trait EnterpriseExtension: Send + Sync {
    fn contract_version(&self) -> &'static str {
        IDENTITY_EXTENSION_VERSION
    }

    /// Authenticate a bearer secret using enterprise-owned credential storage.
    /// Implementations must not log or persist `bearer_token`.
    fn authenticate_bearer(
        &self,
        bearer_token: &str,
    ) -> Result<AuthenticatedPrincipal, ExtensionError>;

    /// Validate a credential and derive all authority in one fail-closed step.
    fn authenticate_context(
        &self,
        bearer_token: &str,
    ) -> Result<AuthenticatedContext, ExtensionError>;

    fn begin_session(&self, _request: SessionRequest) -> Result<Session, ExtensionError> {
        Err(ExtensionError::Unavailable(
            "session issuance is not implemented".into(),
        ))
    }

    fn issue_authorization_code(
        &self,
        _request: AuthorizationCodeRequest,
    ) -> Result<AuthorizationCode, ExtensionError> {
        Err(ExtensionError::Unavailable(
            "authorization-code issuance is not implemented".into(),
        ))
    }

    fn exchange_authorization_code(
        &self,
        _request: AccessCredentialRequest,
    ) -> Result<AccessCredential, ExtensionError> {
        Err(ExtensionError::Unavailable(
            "access-credential issuance is not implemented".into(),
        ))
    }

    fn revoke(&self, _request: RevocationRequest) -> Result<(), ExtensionError> {
        Err(ExtensionError::Unavailable(
            "credential revocation is not implemented".into(),
        ))
    }

    fn authorization_server_metadata(&self) -> Result<AuthorizationServerMetadata, ExtensionError> {
        Err(ExtensionError::Unavailable(
            "authorization-server metadata is not implemented".into(),
        ))
    }

    fn protected_resource_metadata(&self) -> Result<ProtectedResourceMetadata, ExtensionError> {
        Err(ExtensionError::Unavailable(
            "protected-resource metadata is not implemented".into(),
        ))
    }

    fn tenant_context(
        &self,
        principal: &AuthenticatedPrincipal,
    ) -> Result<TenantContext, ExtensionError>;

    fn authorize_namespace(
        &self,
        context: &TenantContext,
        namespace: &str,
        action: NamespaceAction,
    ) -> Result<(), ExtensionError>;

    /// Authorize the complete credential context, including credential scopes.
    ///
    /// Human credentials fail closed unless their validated scope permits the
    /// requested action. Implementations may add narrower policy but must not
    /// bypass this credential-level bound.
    fn authorize_authenticated_context(
        &self,
        context: &AuthenticatedContext,
        namespace: &str,
        action: NamespaceAction,
    ) -> Result<(), ExtensionError> {
        if context.credential_kind == CredentialKind::HumanSession {
            let permitted = match action {
                NamespaceAction::Read => context
                    .scopes
                    .iter()
                    .any(|scope| matches!(scope.as_str(), "sekai.read" | "sekai.write")),
                NamespaceAction::Write => context.scopes.iter().any(|scope| scope == "sekai.write"),
            };
            if !permitted {
                return Err(ExtensionError::PermissionDenied);
            }
        }
        match context.tenant.as_ref() {
            Some(tenant) => self.authorize_namespace(tenant, namespace, action),
            None => self.authorize_unscoped_namespace(&context.principal, namespace, action),
        }
    }

    /// Decide whether a credential authenticated by the community store may
    /// access an enterprise-governed namespace.
    fn authorize_unscoped_namespace(
        &self,
        principal: &AuthenticatedPrincipal,
        namespace: &str,
        action: NamespaceAction,
    ) -> Result<(), ExtensionError>;

    /// Derive allowlisted object-policy inputs from the already validated
    /// credential context. Implementations may add only `x_`-prefixed
    /// attributes and bounded mandatory-control entitlements; request metadata
    /// is never an input to this method.
    fn object_security_context(
        &self,
        context: &AuthenticatedContext,
    ) -> Result<crate::sekai::object_security::PrincipalSecurityContext, ExtensionError> {
        let credential_kind = match context.credential_kind {
            CredentialKind::HumanSession => "human_session",
            CredentialKind::Machine => "machine",
        };
        Ok(crate::sekai::object_security::PrincipalSecurityContext {
            attributes: std::collections::BTreeMap::from([
                ("credential_kind".into(), credential_kind.into()),
                ("issuer".into(), context.issuer.clone()),
                ("subject".into(), context.principal.subject.clone()),
                (
                    "tenant_id".into(),
                    context
                        .tenant
                        .as_ref()
                        .map(|tenant| tenant.tenant_id.clone())
                        .unwrap_or_default(),
                ),
            ]),
            entitlements: context.scopes.iter().cloned().collect(),
        })
    }

    /// Resolve a tenant-scoped model-provider credential (#118).
    ///
    /// Default: unavailable. Enterprise distributions must implement this so
    /// each authenticated tenant supplies isolated provider secrets. Callers
    /// pass only `AuthenticatedContext`; request-selected tenant ids are never
    /// accepted. Implementations must not log or persist secret material.
    fn resolve_provider_credential(
        &self,
        context: &AuthenticatedContext,
        provider: &str,
    ) -> Result<crate::provider_credentials::ResolvedProviderCredential, ExtensionError> {
        let _ = (context, provider);
        Err(ExtensionError::Unavailable(
            "tenant-scoped provider credentials are not implemented".into(),
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    struct FakeExtension;

    impl EnterpriseExtension for FakeExtension {
        fn authenticate_bearer(
            &self,
            bearer_token: &str,
        ) -> Result<AuthenticatedPrincipal, ExtensionError> {
            (bearer_token == "test-token")
                .then(|| AuthenticatedPrincipal {
                    subject: "subject-a".into(),
                    credential_id: "credential-a".into(),
                })
                .ok_or(ExtensionError::CredentialNotFound)
        }

        fn authenticate_context(
            &self,
            bearer_token: &str,
        ) -> Result<AuthenticatedContext, ExtensionError> {
            let principal = self.authenticate_bearer(bearer_token)?;
            Ok(AuthenticatedContext {
                contract_version: IDENTITY_EXTENSION_VERSION,
                tenant: Some(self.tenant_context(&principal)?),
                principal,
                credential_kind: CredentialKind::HumanSession,
                scopes: vec!["sekai.read".into(), "sekai.write".into()],
                issuer: "https://issuer.test".into(),
                resource: "https://sekai.test".into(),
                expires_at: 100,
            })
        }

        fn tenant_context(
            &self,
            principal: &AuthenticatedPrincipal,
        ) -> Result<TenantContext, ExtensionError> {
            Ok(TenantContext {
                tenant_id: "tenant-test".into(),
                subject: principal.subject.clone(),
            })
        }

        fn authorize_namespace(
            &self,
            context: &TenantContext,
            namespace: &str,
            _action: NamespaceAction,
        ) -> Result<(), ExtensionError> {
            (context.tenant_id == "tenant-test" && namespace == "allowed")
                .then_some(())
                .ok_or(ExtensionError::PermissionDenied)
        }

        fn authorize_unscoped_namespace(
            &self,
            _principal: &AuthenticatedPrincipal,
            _namespace: &str,
            _action: NamespaceAction,
        ) -> Result<(), ExtensionError> {
            Err(ExtensionError::PermissionDenied)
        }
    }

    #[test]
    fn deterministic_fake_proves_extension_contract() {
        let extension = FakeExtension;
        assert_eq!(
            extension
                .authenticate_bearer("test-token")
                .unwrap()
                .credential_id,
            "credential-a"
        );
        let context = extension
            .tenant_context(&AuthenticatedPrincipal {
                subject: "subject-a".into(),
                credential_id: "credential-a".into(),
            })
            .unwrap();
        assert!(
            extension
                .authorize_namespace(&context, "allowed", NamespaceAction::Read)
                .is_ok()
        );
        assert_eq!(
            extension.authorize_namespace(&context, "other", NamespaceAction::Write),
            Err(ExtensionError::PermissionDenied)
        );
    }

    #[test]
    fn community_protocol_has_no_tenant_runtime_methods() {
        let protocol = include_str!("../proto/sekai.proto");
        for method in [
            "rpc CreateTenant(",
            "rpc GetTenant(",
            "rpc CreateTenantNamespace(",
            "rpc CreateTenantMembership(",
        ] {
            assert!(
                !protocol.contains(method),
                "unexpected runtime method: {method}"
            );
        }
    }
}
