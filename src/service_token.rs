//! Short-lived service-principal tokens (#1510, ADR 0099).
//!
//! After an identity-extension issuance hook verifies client credentials for a
//! registered, tenant-bound service principal, the plane seals the grant with
//! the same assertion key and prefix-separated token family as #1507 runtime
//! tokens. The authentication boundary verifies that signature and expiry and
//! resolves the caller to the registered service principal — a machine
//! identity, never a user identity.

use serde::{Deserialize, Serialize};

use crate::enterprise::{
    AuthenticatedContext, AuthenticatedPrincipal, CredentialKind, IDENTITY_EXTENSION_VERSION,
    TenantContext,
};
use crate::identity_assertion::{AssertionAuthority, AssertionReject};
use crate::sekai::service_principal::ServicePrincipalRegistration;

pub const SERVICE_TOKEN_VERSION: &str = "sekai.service-token/v1";
pub const SERVICE_TOKEN_PREFIX: &str = "sst1.";
/// Upper bound on one token's lifetime. The extension may request shorter.
pub const SERVICE_TOKEN_MAX_LIFETIME_MS: i64 = 15 * 60 * 1_000;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ServiceTokenClaims {
    pub contract_version: String,
    pub issuer: String,
    pub audience: String,
    /// Registered service principal; never a user subject.
    pub subject: String,
    pub credential_id: String,
    pub tenant_id: String,
    pub namespaces: Vec<String>,
    pub action_types: Vec<String>,
    pub expires_at_ms: i64,
    pub jti: String,
}

impl ServiceTokenClaims {
    /// Claims for `registration` granted by the extension. `None` when the
    /// registration has no tenant: issuance is tenant-bound.
    pub fn for_grant(
        authority: &AssertionAuthority,
        registration: &ServicePrincipalRegistration,
        credential_id: &str,
        expires_at_ms: i64,
        now_ms: i64,
    ) -> Option<Self> {
        if registration.tenant_id.trim().is_empty()
            || credential_id.trim().is_empty()
            || expires_at_ms <= now_ms
        {
            return None;
        }
        Some(Self {
            contract_version: SERVICE_TOKEN_VERSION.into(),
            issuer: authority.issuer.clone(),
            audience: authority.audience.clone(),
            subject: registration.principal.clone(),
            credential_id: credential_id.into(),
            tenant_id: registration.tenant_id.clone(),
            namespaces: registration.namespaces.clone(),
            action_types: registration.action_types.clone(),
            expires_at_ms: expires_at_ms.min(now_ms.saturating_add(SERVICE_TOKEN_MAX_LIFETIME_MS)),
            jti: uuid::Uuid::new_v4().to_string(),
        })
    }

    pub fn sign(&self, authority: &AssertionAuthority) -> Result<String, String> {
        let payload = serde_json::to_vec(self).map_err(|error| error.to_string())?;
        authority.seal(SERVICE_TOKEN_PREFIX, &payload)
    }

    /// Verify signature, version, issuer, audience and expiry. A token is
    /// refused at or after `expires_at_ms`; the issuer is also the verifier,
    /// so no clock tolerance applies.
    pub fn verify(
        authority: &AssertionAuthority,
        token: &str,
        now_ms: i64,
    ) -> Result<Self, AssertionReject> {
        let payload = authority.open(SERVICE_TOKEN_PREFIX, token)?;
        let claims: Self =
            serde_json::from_slice(&payload).map_err(|_| AssertionReject::Signature)?;
        if claims.contract_version != SERVICE_TOKEN_VERSION || claims.issuer != authority.issuer {
            return Err(AssertionReject::Issuer);
        }
        if claims.audience != authority.audience {
            return Err(AssertionReject::Audience);
        }
        if now_ms >= claims.expires_at_ms {
            return Err(AssertionReject::Expiry);
        }
        if [
            &claims.subject,
            &claims.credential_id,
            &claims.tenant_id,
            &claims.jti,
        ]
        .iter()
        .any(|value| value.trim().is_empty())
        {
            return Err(AssertionReject::ScopeEscalation);
        }
        Ok(claims)
    }

    /// The authenticated context callers run under: the registered service
    /// principal as a machine identity, never a human session.
    pub fn authenticated_context(&self) -> AuthenticatedContext {
        AuthenticatedContext {
            contract_version: IDENTITY_EXTENSION_VERSION,
            principal: AuthenticatedPrincipal {
                subject: self.subject.clone(),
                credential_id: format!(
                    "{SERVICE_PRINCIPAL_CREDENTIAL_PREFIX}{}",
                    self.credential_id
                ),
            },
            credential_kind: CredentialKind::Machine,
            tenant: Some(TenantContext {
                tenant_id: self.tenant_id.clone(),
                subject: self.subject.clone(),
            }),
            home_tenant: None,
            space: None,
            space_role: None,
            act: None,
            scopes: Vec::new(),
            issuer: self.issuer.clone(),
            resource: self.audience.clone(),
            expires_at: self.expires_at_ms.div_euclid(1_000),
            device: None,
        }
    }
}

/// Credential-id prefix that marks a context as a registered service
/// principal (#1511), both for service tokens and for runtime tokens derived
/// from them. Scope enforcement keys on it and fails closed when the
/// registration is gone.
pub const SERVICE_PRINCIPAL_CREDENTIAL_PREFIX: &str = "service-principal:";

/// Whether `context` acts as a registered service principal.
pub fn is_service_principal_context(context: &AuthenticatedContext) -> bool {
    context
        .principal
        .credential_id
        .starts_with(SERVICE_PRINCIPAL_CREDENTIAL_PREFIX)
}

pub fn is_service_token(token: &str) -> bool {
    token.starts_with(SERVICE_TOKEN_PREFIX)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::runtime_token::{RUNTIME_TOKEN_PREFIX, RuntimeTokenClaims};

    fn authority() -> AssertionAuthority {
        AssertionAuthority::new("https://issuer.test", "https://sekai.test", b"key")
    }

    fn registration() -> ServicePrincipalRegistration {
        ServicePrincipalRegistration {
            principal: "worker-a".into(),
            tenant_id: "tenant-a".into(),
            namespaces: vec!["ns-a".into()],
            action_types: vec!["dispatch".into()],
            registered_by: "root".into(),
            created_at_ms: 1,
            updated_at_ms: 1,
        }
    }

    #[test]
    fn verify_refuses_expiry_and_foreign_token_families() {
        let authority = authority();
        let claims =
            ServiceTokenClaims::for_grant(&authority, &registration(), "cred-a", 5_000, 0).unwrap();
        let token = claims.sign(&authority).unwrap();
        assert!(is_service_token(&token));
        assert_eq!(
            ServiceTokenClaims::verify(&authority, &token, 4_999).unwrap(),
            claims
        );
        assert_eq!(
            ServiceTokenClaims::verify(&authority, &token, 5_000).unwrap_err(),
            AssertionReject::Expiry
        );
        let other = AssertionAuthority::new("https://issuer.test", "https://sekai.test", b"k2");
        assert_eq!(
            ServiceTokenClaims::verify(&other, &token, 0).unwrap_err(),
            AssertionReject::Signature
        );
        assert_eq!(
            authority.verify(&token, 0, None).unwrap_err(),
            AssertionReject::Signature
        );
        assert!(!token.starts_with(RUNTIME_TOKEN_PREFIX));
        assert_eq!(
            RuntimeTokenClaims::verify(&authority, &token, 0).unwrap_err(),
            AssertionReject::Signature
        );
        let context = claims.authenticated_context();
        assert_eq!(context.principal.subject, "worker-a");
        assert_eq!(context.credential_kind, CredentialKind::Machine);
        assert_ne!(context.credential_kind, CredentialKind::HumanSession);
    }

    #[test]
    fn no_token_without_tenant_or_live_grant() {
        let authority = authority();
        let mut tenantless = registration();
        tenantless.tenant_id.clear();
        assert!(
            ServiceTokenClaims::for_grant(&authority, &tenantless, "cred-a", 5_000, 0).is_none()
        );
        assert!(
            ServiceTokenClaims::for_grant(&authority, &registration(), " ", 5_000, 0).is_none()
        );
        assert!(
            ServiceTokenClaims::for_grant(&authority, &registration(), "cred-a", 0, 0).is_none()
        );
    }

    #[test]
    fn lifetime_never_exceeds_max() {
        let claims =
            ServiceTokenClaims::for_grant(&authority(), &registration(), "cred-a", i64::MAX, 0)
                .unwrap();
        assert_eq!(claims.expires_at_ms, SERVICE_TOKEN_MAX_LIFETIME_MS);
    }
}
