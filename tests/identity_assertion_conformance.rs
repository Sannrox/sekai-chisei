//! Audience-bound identity assertion conformance (#888 / ADR 0078).

use sekai_chisei::enterprise::{
    AuthenticatedContext, AuthenticatedPrincipal, CredentialKind, EnterpriseExtension,
    ExtensionError, IDENTITY_EXTENSION_VERSION, NamespaceAction, TenantContext,
};
use sekai_chisei::identity_assertion::{
    AssertionAuthority, AssertionReject, IDENTITY_ASSERTION_VERSION, IdentityAssertion,
};

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
fn assertion_path_matches_in_process_extension_authorization() {
    let extension = FakeExtension;
    let in_process = extension.authenticate_context("test-token").unwrap();
    let authority = AssertionAuthority::new(
        in_process.issuer.clone(),
        in_process.resource.clone(),
        b"key",
    );
    let token = authority
        .sign(&IdentityAssertion {
            contract_version: IDENTITY_ASSERTION_VERSION.into(),
            issuer: in_process.issuer.clone(),
            audience: in_process.resource.clone(),
            subject: in_process.principal.subject.clone(),
            credential_id: in_process.principal.credential_id.clone(),
            credential_kind: "human_session".into(),
            tenant_id: in_process
                .tenant
                .as_ref()
                .map(|tenant| tenant.tenant_id.clone()),
            scopes: in_process.scopes.clone(),
            expires_at: in_process.expires_at,
            nonce: "parity-1".into(),
        })
        .unwrap();
    let via_assertion = authority.verify(&token, 50, None).unwrap();
    assert_eq!(via_assertion.principal, in_process.principal);
    assert_eq!(via_assertion.scopes, in_process.scopes);
    assert_eq!(via_assertion.tenant, in_process.tenant);
    assert_eq!(
        extension.authorize_authenticated_context(&via_assertion, "allowed", NamespaceAction::Read),
        extension.authorize_authenticated_context(&in_process, "allowed", NamespaceAction::Read)
    );
    assert_eq!(
        extension.authorize_authenticated_context(&via_assertion, "other", NamespaceAction::Write),
        Err(ExtensionError::PermissionDenied)
    );
}

#[test]
fn conformance_kit_names_each_failure_class() {
    let authority = AssertionAuthority::new("https://issuer.test", "https://sekai.test", b"key");
    let mut claims = IdentityAssertion {
        contract_version: IDENTITY_ASSERTION_VERSION.into(),
        issuer: "https://issuer.test".into(),
        audience: "https://sekai.test".into(),
        subject: "subject-a".into(),
        credential_id: "credential-a".into(),
        credential_kind: "human_session".into(),
        tenant_id: None,
        scopes: vec!["sekai.read".into()],
        expires_at: 100,
        nonce: "kit-1".into(),
    };
    let token = authority.sign(&claims).unwrap();
    assert_eq!(
        authority.verify(&token, 50, Some("t")).unwrap_err(),
        AssertionReject::CallerTenantHeader
    );
    claims.nonce = "kit-iss".into();
    claims.issuer = "https://other".into();
    assert_eq!(
        authority
            .verify(&authority.sign(&claims).unwrap(), 50, None)
            .unwrap_err(),
        AssertionReject::Issuer
    );
}
