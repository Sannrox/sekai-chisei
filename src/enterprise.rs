//! Backend-neutral contracts for composing enterprise authority into the control plane.
//!
//! The community runtime does not install an implementation and never derives
//! tenant authority from request metadata. Enterprise distributions may inject
//! an implementation while retaining one authoritative service process.

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuthenticatedPrincipal {
    pub subject: String,
    pub credential_id: String,
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
    Unavailable(String),
}

/// Injection boundary implemented by an enterprise composition.
///
/// Implementations derive context only from an authenticated principal and
/// make the tenant/namespace decision before the core accesses durable data.
pub trait EnterpriseExtension: Send + Sync {
    /// Authenticate a bearer secret using enterprise-owned credential storage.
    /// Implementations must not log or persist `bearer_token`.
    fn authenticate_bearer(
        &self,
        bearer_token: &str,
    ) -> Result<AuthenticatedPrincipal, ExtensionError>;

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

    /// Decide whether a credential authenticated by the community store may
    /// access an enterprise-governed namespace.
    fn authorize_unscoped_namespace(
        &self,
        principal: &AuthenticatedPrincipal,
        namespace: &str,
        action: NamespaceAction,
    ) -> Result<(), ExtensionError>;
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
