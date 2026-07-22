use std::collections::{HashMap, HashSet};
use std::sync::Mutex;

use sekai_chisei::enterprise::*;

const ISSUER: &str = "https://identity.example.test";
const RESOURCE: &str = "https://sekai.example.test";
const REDIRECT: &str = "https://client.example.test/callback";

#[derive(Debug, Clone)]
struct CodeState {
    request: AuthorizationCodeRequest,
    expires_at: i64,
    used: bool,
}

#[derive(Default)]
struct FakeIdentityExtension {
    sessions: Mutex<HashMap<String, Session>>,
    codes: Mutex<HashMap<String, CodeState>>,
    credentials: Mutex<HashMap<String, AuthenticatedContext>>,
    revoked: Mutex<HashSet<String>>,
    membership_revoked: Mutex<bool>,
    tenant_suspended: Mutex<bool>,
}

impl FakeIdentityExtension {
    fn issue(&self) -> AccessCredential {
        let session = self
            .begin_session(SessionRequest {
                state: "state-1".into(),
                nonce: "nonce-1".into(),
                redirect_uri: REDIRECT.into(),
                issuer: ISSUER.into(),
            })
            .unwrap();
        let code = self
            .issue_authorization_code(AuthorizationCodeRequest {
                session_id: session.id,
                state: session.state,
                nonce: session.nonce,
                redirect_uri: REDIRECT.into(),
                code_challenge: "verifier-1".into(),
                scopes: vec!["sekai.read".into()],
                resource: RESOURCE.into(),
            })
            .unwrap();
        self.exchange_authorization_code(AccessCredentialRequest {
            code: code.code,
            code_verifier: SecretValue::new("verifier-1"),
            redirect_uri: REDIRECT.into(),
            issuer: ISSUER.into(),
            resource: RESOURCE.into(),
        })
        .unwrap()
    }
}

impl EnterpriseExtension for FakeIdentityExtension {
    fn authenticate_bearer(
        &self,
        bearer_token: &str,
    ) -> Result<AuthenticatedPrincipal, ExtensionError> {
        self.authenticate_context(bearer_token)
            .map(|context| context.principal)
    }

    fn authenticate_context(
        &self,
        bearer_token: &str,
    ) -> Result<AuthenticatedContext, ExtensionError> {
        if self.revoked.lock().unwrap().contains(bearer_token) {
            return Err(ExtensionError::Revoked);
        }
        if *self.membership_revoked.lock().unwrap() {
            return Err(ExtensionError::MembershipRevoked);
        }
        if *self.tenant_suspended.lock().unwrap() {
            return Err(ExtensionError::TenantSuspended);
        }
        self.credentials
            .lock()
            .unwrap()
            .get(bearer_token)
            .cloned()
            .ok_or(ExtensionError::CredentialNotFound)
    }

    fn begin_session(&self, request: SessionRequest) -> Result<Session, ExtensionError> {
        if request.issuer != ISSUER {
            return Err(ExtensionError::IssuerMismatch);
        }
        if request.redirect_uri != REDIRECT {
            return Err(ExtensionError::InvalidRedirectUri);
        }
        let session = Session {
            id: "session-1".into(),
            state: request.state,
            nonce: request.nonce,
            redirect_uri: request.redirect_uri,
            issuer: request.issuer,
            expires_at: 200,
        };
        self.sessions
            .lock()
            .unwrap()
            .insert(session.id.clone(), session.clone());
        Ok(session)
    }

    fn issue_authorization_code(
        &self,
        request: AuthorizationCodeRequest,
    ) -> Result<AuthorizationCode, ExtensionError> {
        let sessions = self.sessions.lock().unwrap();
        let session = sessions
            .get(&request.session_id)
            .ok_or(ExtensionError::Unauthenticated)?;
        if request.state != session.state {
            return Err(ExtensionError::InvalidState);
        }
        if request.nonce != session.nonce {
            return Err(ExtensionError::InvalidNonce);
        }
        if request.redirect_uri != session.redirect_uri {
            return Err(ExtensionError::InvalidRedirectUri);
        }
        if request.resource != RESOURCE {
            return Err(ExtensionError::ResourceMismatch);
        }
        drop(sessions);
        let code = "code-1".to_string();
        self.codes.lock().unwrap().insert(
            code.clone(),
            CodeState {
                request,
                expires_at: 150,
                used: false,
            },
        );
        Ok(AuthorizationCode {
            code: SecretValue::new(code),
            expires_at: 150,
        })
    }

    fn exchange_authorization_code(
        &self,
        request: AccessCredentialRequest,
    ) -> Result<AccessCredential, ExtensionError> {
        if request.issuer != ISSUER {
            return Err(ExtensionError::IssuerMismatch);
        }
        if request.resource != RESOURCE {
            return Err(ExtensionError::ResourceMismatch);
        }
        let mut codes = self.codes.lock().unwrap();
        let code = codes
            .get_mut(request.code.expose())
            .ok_or(ExtensionError::Unauthenticated)?;
        if code.used {
            return Err(ExtensionError::Replayed);
        }
        if code.expires_at <= 100 {
            return Err(ExtensionError::Expired);
        }
        if code.request.redirect_uri != request.redirect_uri {
            return Err(ExtensionError::InvalidRedirectUri);
        }
        if code.request.code_challenge != request.code_verifier.expose() {
            return Err(ExtensionError::InvalidPkce);
        }
        code.used = true;
        let context = AuthenticatedContext {
            contract_version: IDENTITY_EXTENSION_VERSION,
            principal: AuthenticatedPrincipal {
                subject: "human:alice".into(),
                credential_id: "credential-1".into(),
            },
            credential_kind: CredentialKind::HumanSession,
            tenant: Some(TenantContext {
                tenant_id: "tenant-1".into(),
                subject: "human:alice".into(),
            }),
            scopes: code.request.scopes.clone(),
            issuer: ISSUER.into(),
            resource: RESOURCE.into(),
            expires_at: 300,
        };
        let token = "access-1";
        self.credentials
            .lock()
            .unwrap()
            .insert(token.into(), context.clone());
        Ok(AccessCredential {
            credential: SecretValue::new(token),
            context,
        })
    }

    fn revoke(&self, request: RevocationRequest) -> Result<(), ExtensionError> {
        self.revoked
            .lock()
            .unwrap()
            .insert(request.credential.expose().into());
        Ok(())
    }

    fn tenant_context(
        &self,
        principal: &AuthenticatedPrincipal,
    ) -> Result<TenantContext, ExtensionError> {
        Ok(TenantContext {
            tenant_id: "tenant-1".into(),
            subject: principal.subject.clone(),
        })
    }

    fn authorize_namespace(
        &self,
        context: &TenantContext,
        namespace: &str,
        _action: NamespaceAction,
    ) -> Result<(), ExtensionError> {
        (context.tenant_id == "tenant-1" && namespace == "tenant-1:default")
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

    fn authorization_server_metadata(&self) -> Result<AuthorizationServerMetadata, ExtensionError> {
        Ok(AuthorizationServerMetadata {
            contract_version: AUTHORIZATION_SERVER_METADATA_VERSION,
            issuer: ISSUER.into(),
            authorization_endpoint: format!("{ISSUER}/authorize"),
            token_endpoint: format!("{ISSUER}/token"),
            revocation_endpoint: format!("{ISSUER}/revoke"),
            scopes_supported: vec!["sekai.read".into()],
            code_challenge_methods_supported: vec!["S256".into()],
        })
    }

    fn protected_resource_metadata(&self) -> Result<ProtectedResourceMetadata, ExtensionError> {
        Ok(ProtectedResourceMetadata {
            contract_version: PROTECTED_RESOURCE_METADATA_VERSION,
            resource: RESOURCE.into(),
            authorization_servers: vec![ISSUER.into()],
            scopes_supported: vec!["sekai.read".into()],
        })
    }
}

#[test]
fn deterministic_fake_proves_lifecycle_validation_and_revocation() {
    let extension = FakeIdentityExtension::default();
    let credential = extension.issue();
    credential.context.validate(100, ISSUER, RESOURCE).unwrap();
    assert_eq!(credential.context.scopes, ["sekai.read"]);
    assert!(
        extension
            .authorize_authenticated_context(
                &credential.context,
                "tenant-1:default",
                NamespaceAction::Read,
            )
            .is_ok()
    );
    assert_eq!(
        extension.authorize_authenticated_context(
            &credential.context,
            "tenant-1:default",
            NamespaceAction::Write,
        ),
        Err(ExtensionError::PermissionDenied)
    );
    assert_eq!(
        extension
            .exchange_authorization_code(AccessCredentialRequest {
                code: SecretValue::new("code-1"),
                code_verifier: SecretValue::new("verifier-1"),
                redirect_uri: REDIRECT.into(),
                issuer: ISSUER.into(),
                resource: RESOURCE.into(),
            })
            .unwrap_err(),
        ExtensionError::Replayed
    );
    extension
        .revoke(RevocationRequest {
            credential: credential.credential.clone(),
        })
        .unwrap();
    assert_eq!(
        extension.authenticate_context(credential.credential.expose()),
        Err(ExtensionError::Revoked)
    );
}

#[test]
fn deterministic_fake_fails_closed_for_each_bound_value() {
    let extension = FakeIdentityExtension::default();
    assert_eq!(
        extension.begin_session(SessionRequest {
            state: "state".into(),
            nonce: "nonce".into(),
            redirect_uri: "https://attacker.test/callback".into(),
            issuer: ISSUER.into(),
        }),
        Err(ExtensionError::InvalidRedirectUri)
    );
    let session = extension
        .begin_session(SessionRequest {
            state: "state-1".into(),
            nonce: "nonce-1".into(),
            redirect_uri: REDIRECT.into(),
            issuer: ISSUER.into(),
        })
        .unwrap();
    let request = |state: &str, nonce: &str| AuthorizationCodeRequest {
        session_id: session.id.clone(),
        state: state.into(),
        nonce: nonce.into(),
        redirect_uri: REDIRECT.into(),
        code_challenge: "verifier-1".into(),
        scopes: vec!["sekai.read".into()],
        resource: RESOURCE.into(),
    };
    assert_eq!(
        extension.issue_authorization_code(request("wrong", "nonce-1")),
        Err(ExtensionError::InvalidState)
    );
    assert_eq!(
        extension.issue_authorization_code(request("state-1", "wrong")),
        Err(ExtensionError::InvalidNonce)
    );
    let code = extension
        .issue_authorization_code(request("state-1", "nonce-1"))
        .unwrap();
    assert_eq!(
        extension.exchange_authorization_code(AccessCredentialRequest {
            code: code.code,
            code_verifier: SecretValue::new("wrong"),
            redirect_uri: REDIRECT.into(),
            issuer: ISSUER.into(),
            resource: RESOURCE.into(),
        }),
        Err(ExtensionError::InvalidPkce)
    );

    let extension = FakeIdentityExtension::default();
    let credential = extension.issue();
    assert_eq!(
        credential
            .context
            .validate(100, "https://other.test", RESOURCE),
        Err(ExtensionError::IssuerMismatch)
    );
    assert_eq!(
        credential
            .context
            .validate(100, ISSUER, "https://other.test"),
        Err(ExtensionError::ResourceMismatch)
    );
    assert_eq!(
        credential.context.validate(300, ISSUER, RESOURCE),
        Err(ExtensionError::Expired)
    );
}

#[test]
fn membership_and_tenant_state_are_rechecked_on_every_authentication() {
    let extension = FakeIdentityExtension::default();
    let credential = extension.issue();
    *extension.membership_revoked.lock().unwrap() = true;
    assert_eq!(
        extension.authenticate_context(credential.credential.expose()),
        Err(ExtensionError::MembershipRevoked)
    );
    *extension.membership_revoked.lock().unwrap() = false;
    *extension.tenant_suspended.lock().unwrap() = true;
    assert_eq!(
        extension.authenticate_context(credential.credential.expose()),
        Err(ExtensionError::TenantSuspended)
    );
}

#[test]
fn credential_material_is_redacted_and_metadata_contracts_are_versioned() {
    let extension = FakeIdentityExtension::default();
    let credential = extension.issue();
    let rendered = format!("{credential:?}");
    assert!(rendered.contains("[REDACTED]"));
    assert!(!rendered.contains(credential.credential.expose()));
    assert_eq!(
        extension
            .authorization_server_metadata()
            .unwrap()
            .contract_version,
        AUTHORIZATION_SERVER_METADATA_VERSION
    );
    assert_eq!(
        extension
            .protected_resource_metadata()
            .unwrap()
            .contract_version,
        PROTECTED_RESOURCE_METADATA_VERSION
    );
}

#[test]
fn community_build_has_no_identity_endpoints_or_activation_configuration() {
    let gateway = include_str!("../src/gateway.rs");
    let config = include_str!("../src/config.rs");
    for endpoint in [
        "/.well-known/openid-configuration",
        "/.well-known/oauth-authorization-server",
        "/.well-known/oauth-protected-resource",
        "/oauth/authorize",
        "/oauth/token",
        "/oauth/revoke",
        "/session",
    ] {
        assert!(!gateway.contains(&format!("route(\"{endpoint}\"")));
    }
    for variable in ["SEKAI_OIDC", "SEKAI_OAUTH", "SEKAI_IDENTITY_EXTENSION"] {
        assert!(!config.contains(variable));
    }
}
