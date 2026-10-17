//! Backend-neutral contracts for composing enterprise authority into the control plane.
//!
//! The community runtime does not install an implementation and never derives
//! tenant authority from request metadata. Enterprise distributions may inject
//! an implementation while retaining one authoritative service process.

use std::fmt;

pub const IDENTITY_EXTENSION_VERSION: &str = "sekai.identity-extension/v2";
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

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CredentialKind {
    HumanSession,
    Machine,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SpaceRole {
    Discoverer,
    Viewer,
    Editor,
    Approver,
    Administrator,
}

/// What a host tenant granted one guest on one namespace (#1433). The host
/// tenant chooses both; the guest's home-tenant authority never widens them.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GuestGrant {
    pub role: SpaceRole,
    /// Highest `access_marking` the guest may see or write in the namespace.
    /// Core evaluates this against the namespace's activated lattice when one
    /// exists, otherwise against the default evidence ordinal.
    pub marking_ceiling: String,
}

impl GuestGrant {
    /// Discover needs any role, read a viewer role or above, write an editor
    /// or administrator. Approver adds nothing: guests never approve.
    pub fn permits(&self, action: NamespaceAction) -> bool {
        match action {
            NamespaceAction::Discover => true,
            NamespaceAction::Read => !matches!(self.role, SpaceRole::Discoverer),
            NamespaceAction::Write => {
                matches!(self.role, SpaceRole::Editor | SpaceRole::Administrator)
            }
        }
    }
}

/// What the owning tenant currently exposes through a shared space (#1434).
///
/// Membership needs approval from both the owning tenant and the member's
/// home tenant. The extension owns those approvals and the exposure list;
/// core enforces the returned namespaces, kinds, and marking ceiling and
/// asks again on every request.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SharedSpaceGrant {
    /// Tenant that owns the space and the exposed resources.
    pub owner_tenant: String,
    /// Owner namespaces visible through the space.
    pub namespaces: Vec<String>,
    /// Object kinds visible through the space.
    pub kinds: Vec<String>,
    /// Highest `access_marking` visible through the space.
    pub marking_ceiling: String,
}

impl SharedSpaceGrant {
    pub fn exposes_namespace(&self, namespace: &str) -> bool {
        self.namespaces.iter().any(|exposed| exposed == namespace)
    }

    pub fn exposes_kind(&self, kind: &str) -> bool {
        self.kinds.iter().any(|exposed| exposed == kind)
    }
}

/// Outcome of [`EnterpriseExtension::authorize_shared_space`].
///
/// `Denied` still names the owning tenant so core can audit
/// `tenant.shared_space_access.resource_tenant` without treating the
/// member's home tenant as the resource owner.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SharedSpaceAuthorization {
    Unshared,
    Granted(SharedSpaceGrant),
    Denied { owner_tenant: String },
}

impl SharedSpaceAuthorization {
    pub fn owner_tenant(&self) -> Option<&str> {
        match self {
            Self::Unshared => None,
            Self::Granted(grant) => Some(grant.owner_tenant.as_str()),
            Self::Denied { owner_tenant } => Some(owner_tenant.as_str()),
        }
    }
}

/// What one tenant currently allows another to find (#1435). Listing a
/// tenant, principal, space, or namespace is not a read. Default: nothing
/// is discoverable across tenants.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DiscoveryRule {
    pub owner_tenant: String,
    pub tenants: Vec<String>,
    pub principals: Vec<String>,
    pub spaces: Vec<String>,
    pub namespaces: Vec<String>,
}

impl DiscoveryRule {
    pub fn exposes_tenant(&self, tenant: &str) -> bool {
        self.tenants.iter().any(|exposed| exposed == tenant)
    }

    pub fn exposes_principal(&self, principal: &str) -> bool {
        self.principals.iter().any(|exposed| exposed == principal)
    }

    pub fn exposes_space(&self, space: &str) -> bool {
        self.spaces.iter().any(|exposed| exposed == space)
    }

    pub fn exposes_namespace(&self, namespace: &str) -> bool {
        self.namespaces.iter().any(|exposed| exposed == namespace)
    }
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
    /// Acting tenant: the tenant whose namespaces this context addresses.
    pub tenant: Option<TenantContext>,
    /// The principal's home tenant when it differs from the acting tenant
    /// (a guest). `None` means the principal belongs to the acting tenant.
    pub home_tenant: Option<String>,
    pub space: Option<String>,
    pub space_role: Option<SpaceRole>,
    /// Human subject resolved by the trusted validator; never an unverified routing hint.
    pub act: Option<String>,
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
            space: None,
            space_role: None,
            act: None,
            tenant: None,
            home_tenant: None,
            scopes: Vec::new(),
            issuer: "sekai:community".into(),
            resource: "sekai:control-plane".into(),
            expires_at: i64::MAX,
        }
    }

    /// The home tenant of a guest context: one whose principal belongs to a
    /// tenant other than the acting tenant. `None` for same-tenant contexts.
    pub fn guest_home_tenant(&self) -> Option<&str> {
        let home = self.home_tenant.as_deref()?;
        let acting = self.tenant.as_ref().map(|tenant| tenant.tenant_id.as_str());
        (acting != Some(home)).then_some(home)
    }

    /// A non-guest context that names a space. Shared-space membership
    /// (#1434) is decided by the extension; unshared spaces keep today's path.
    pub fn named_space(&self) -> Option<&str> {
        if self.guest_home_tenant().is_some() {
            return None;
        }
        self.space
            .as_deref()
            .filter(|space| !space.trim().is_empty())
    }

    /// Home tenant of a shared-space member: they act under their own tenant.
    pub fn home_tenant_id(&self) -> Option<&str> {
        self.tenant
            .as_ref()
            .map(|tenant| tenant.tenant_id.as_str())
            .filter(|tenant| !tenant.trim().is_empty())
    }

    pub fn authorize_space(&self, action: NamespaceAction) -> Result<(), ExtensionError> {
        // A home tenant is only meaningful next to a non-empty acting tenant.
        if self.home_tenant.as_ref().is_some_and(|home| {
            home.trim().is_empty()
                || self
                    .tenant
                    .as_ref()
                    .is_none_or(|tenant| tenant.tenant_id.trim().is_empty())
        }) {
            return Err(ExtensionError::PermissionDenied);
        }
        if self
            .space
            .as_ref()
            .is_some_and(|space| space.trim().is_empty())
            || (self.space_role.is_some() && self.space.is_none())
            || (self.space.is_some()
                && self
                    .tenant
                    .as_ref()
                    .is_none_or(|tenant| tenant.tenant_id.trim().is_empty()))
            || self
                .act
                .as_ref()
                .is_some_and(|actor| actor.trim().is_empty() || actor == &self.principal.subject)
        {
            return Err(ExtensionError::PermissionDenied);
        }
        if self.space.is_none() {
            return Ok(());
        }
        let permitted = match action {
            NamespaceAction::Discover => self.space_role.is_some(),
            NamespaceAction::Read => matches!(
                self.space_role,
                Some(
                    SpaceRole::Viewer
                        | SpaceRole::Editor
                        | SpaceRole::Approver
                        | SpaceRole::Administrator
                )
            ),
            NamespaceAction::Write => matches!(
                self.space_role,
                Some(SpaceRole::Editor | SpaceRole::Administrator)
            ),
        };
        if permitted {
            Ok(())
        } else {
            Err(ExtensionError::PermissionDenied)
        }
    }

    pub fn authorize_credential_scope(
        &self,
        action: NamespaceAction,
    ) -> Result<(), ExtensionError> {
        if self.credential_kind != CredentialKind::HumanSession {
            return Ok(());
        }
        let permitted = match action {
            NamespaceAction::Discover => self.scopes.iter().any(|scope| {
                matches!(
                    scope.as_str(),
                    "sekai.discover" | "sekai.read" | "sekai.write"
                )
            }),
            NamespaceAction::Read => self
                .scopes
                .iter()
                .any(|scope| matches!(scope.as_str(), "sekai.read" | "sekai.write")),
            NamespaceAction::Write => self.scopes.iter().any(|scope| scope == "sekai.write"),
        };
        if permitted {
            Ok(())
        } else {
            Err(ExtensionError::PermissionDenied)
        }
    }

    /// Guests never approve; approval stays with the acting tenant's members.
    pub fn authorize_space_approval(&self) -> Result<(), ExtensionError> {
        self.authorize_space(NamespaceAction::Read)?;
        if self.guest_home_tenant().is_some() {
            return Err(ExtensionError::PermissionDenied);
        }
        if self.space.is_none()
            || matches!(
                self.space_role,
                Some(SpaceRole::Approver | SpaceRole::Administrator)
            )
        {
            Ok(())
        } else {
            Err(ExtensionError::PermissionDenied)
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

/// Machine-readable refusal when `act` can no longer authorize claim or apply.
pub const DELEGATOR_DISABLED: &str = "delegator_disabled";
pub const DELEGATOR_NOT_MEMBER: &str = "delegator_not_member";
pub const DELEGATOR_GRANT_MISSING: &str = "delegator_grant_missing";
pub const DELEGATOR_RECORD_MISSING: &str = "delegator_record_missing";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DelegatorApplyRefusal {
    Disabled,
    NotMember,
    GrantMissing,
    RecordMissing,
}

impl DelegatorApplyRefusal {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Disabled => DELEGATOR_DISABLED,
            Self::NotMember => DELEGATOR_NOT_MEMBER,
            Self::GrantMissing => DELEGATOR_GRANT_MISSING,
            Self::RecordMissing => DELEGATOR_RECORD_MISSING,
        }
    }
}

/// Live facts about the delegating principal, loaded at claim and apply.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DelegatingPrincipalState {
    pub enabled: bool,
    pub tenant_member: bool,
    pub holds_needed_grant: bool,
}

/// Re-validate `act` at claim and apply. Absent or empty `act` is a no-op.
pub fn revalidate_delegating_principal(
    act: Option<&str>,
    state: DelegatingPrincipalState,
) -> Result<(), DelegatorApplyRefusal> {
    if act.is_none_or(|actor| actor.trim().is_empty()) {
        return Ok(());
    }
    if !state.enabled {
        return Err(DelegatorApplyRefusal::Disabled);
    }
    if !state.tenant_member {
        return Err(DelegatorApplyRefusal::NotMember);
    }
    if !state.holds_needed_grant {
        return Err(DelegatorApplyRefusal::GrantMissing);
    }
    Ok(())
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

/// Client-credentials input for a registered service principal (#1510).
///
/// Core supplies the live registration; the extension only verifies the
/// secret it owns. Debug redacts `client_secret`.
#[derive(Clone, PartialEq, Eq)]
pub struct ServicePrincipalTokenRequest {
    pub principal: String,
    pub client_secret: SecretValue,
    pub tenant_id: String,
    pub namespaces: Vec<String>,
    pub action_types: Vec<String>,
}

impl fmt::Debug for ServicePrincipalTokenRequest {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ServicePrincipalTokenRequest")
            .field("principal", &self.principal)
            .field("client_secret", &"[REDACTED]")
            .field("tenant_id", &self.tenant_id)
            .field("namespaces", &self.namespaces)
            .field("action_types", &self.action_types)
            .finish()
    }
}

/// Extension grant after client-credentials verification. Core signs the
/// returned identity as a service token; `expires_at_ms` is a millisecond
/// Unix timestamp.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ServicePrincipalTokenGrant {
    pub credential_id: String,
    pub expires_at_ms: i64,
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

/// Namespace permission lattice. `Discover` is strictly below `Read`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NamespaceAction {
    Discover,
    Read,
    Write,
}

/// The model a provider call will reach, resolved before any credential lookup (#1352).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ModelIdentity {
    pub provider: String,
    /// Canonical model id after alias resolution.
    pub model: String,
    pub upstream_model: String,
    pub profile_version: String,
    /// Pinned weights digest, when the provider profile carries one.
    pub artifact_digest: Option<String>,
    /// Base URL of the endpoint that will receive the prompt.
    pub endpoint: String,
}

/// Isolated-process work about to be returned to a runner (#1588).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IsolatedProcessJob {
    pub run_id: String,
    pub namespace: String,
    /// Seconds the runner is expected to hold. `0` means the extension should
    /// apply its own estimate.
    pub estimated_seconds: i64,
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
        context.authorize_space(action)?;
        context.authorize_credential_scope(action)?;
        if context.guest_home_tenant().is_some() {
            let grant = self.authorize_guest_namespace(context, namespace, action)?;
            return if grant.permits(action) {
                Ok(())
            } else {
                Err(ExtensionError::PermissionDenied)
            };
        }
        match context.tenant.as_ref() {
            Some(tenant) => self.authorize_namespace(tenant, namespace, action),
            None => self.authorize_unscoped_namespace(&context.principal, namespace, action),
        }
    }

    /// The host tenant's current grant for a guest context (see
    /// [`AuthenticatedContext::guest_home_tenant`]) on a namespace of its
    /// acting tenant. Default: denied, so cross-tenant access stays off until
    /// an extension opts in explicitly. Core calls this on every guest
    /// decision, even when `authorize_authenticated_context` is overridden,
    /// and enforces the returned role and marking ceiling itself. It is asked
    /// again on every request, so a revoked or narrowed grant applies to the
    /// next one.
    fn authorize_guest_namespace(
        &self,
        context: &AuthenticatedContext,
        namespace: &str,
        action: NamespaceAction,
    ) -> Result<GuestGrant, ExtensionError> {
        let _ = (context, namespace, action);
        Err(ExtensionError::PermissionDenied)
    }

    /// Current shared-space decision for a non-guest context that names a
    /// space (#1434). `Unshared` keeps today's same-tenant path.
    /// `Granted` admits only the exposed namespaces, kinds, and markings
    /// after both the owning tenant and the member's home tenant approved
    /// membership. `Denied` refuses one-sided approval, withdrawal, or a
    /// space that does not expose this namespace, and still names the
    /// owning tenant for audit. Default: unshared. Core calls this on
    /// every request and caches nothing, so withdrawal applies to the next
    /// one.
    fn authorize_shared_space(
        &self,
        context: &AuthenticatedContext,
        namespace: &str,
        action: NamespaceAction,
    ) -> Result<SharedSpaceAuthorization, ExtensionError> {
        let _ = (context, namespace, action);
        Ok(SharedSpaceAuthorization::Unshared)
    }

    /// Current discovery rule for a caller looking at `owner_tenant` (#1435).
    /// `Ok(None)` means no rule: cross-tenant listing and lookup look the
    /// same as a missing target. `Ok(Some(rule))` names the tenants,
    /// principals, spaces, and namespaces that may be found, at discover
    /// level only. `Err` denies a withdrawn or one-sided rule. Default: no
    /// rule. Core calls this on every discover request and caches nothing.
    fn authorize_discovery(
        &self,
        context: &AuthenticatedContext,
        owner_tenant: &str,
    ) -> Result<Option<DiscoveryRule>, ExtensionError> {
        let _ = (context, owner_tenant);
        Ok(None)
    }

    /// Decide whether a credential authenticated by the community store may
    /// access an enterprise-governed namespace.
    fn authorize_unscoped_namespace(
        &self,
        principal: &AuthenticatedPrincipal,
        namespace: &str,
        action: NamespaceAction,
    ) -> Result<(), ExtensionError>;

    /// Re-validate a named delegating actor (`act`) at apply.
    ///
    /// Default: unavailable. Community apply uses principal credentials and
    /// namespace grants when no extension is installed. An installed extension
    /// must implement this so enterprise enablement, membership, and grants
    /// are authoritative.
    fn authorize_delegating_principal(
        &self,
        principal: &str,
        namespace: &str,
        action: NamespaceAction,
    ) -> Result<(), ExtensionError> {
        let _ = (principal, namespace, action);
        Err(ExtensionError::Unavailable(
            "delegating principal revalidation is not implemented".into(),
        ))
    }

    /// Admit or refuse the resolved model of a provider execution before its
    /// credential lookup and provider call (#1352), for keyed and keyless
    /// providers alike. Operator-configured internal models (leak reviewer,
    /// scoring, evaluation) are not tenant routes and do not pass through it.
    ///
    /// Default: admit. Return `PermissionDenied` to deny or `Unavailable` when
    /// the admission policy cannot decide; either refuses execution.
    fn admit_model(
        &self,
        context: &AuthenticatedContext,
        model: &ModelIdentity,
    ) -> Result<(), ExtensionError> {
        let _ = (context, model);
        Ok(())
    }

    /// Admit or refuse an isolated-process claim before the runner receives
    /// it (#1588). Community `TenantQuotaGate` still runs separately.
    ///
    /// Default: admit. Return `PermissionDenied` to skip and defer this claim,
    /// or `Unavailable` when the admission policy cannot decide.
    fn admit_isolated_process_job(
        &self,
        context: &AuthenticatedContext,
        job: &IsolatedProcessJob,
    ) -> Result<(), ExtensionError> {
        let _ = (context, job);
        Ok(())
    }

    /// Resolve a tenant-scoped model-provider credential (#118).
    ///
    /// Default: unavailable. Enterprise distributions must implement this so
    /// each authenticated tenant supplies isolated provider secrets. Callers
    /// pass only `AuthenticatedContext`; request-selected tenant ids are never
    /// accepted. Implementations must not log or persist secret material.
    ///
    /// Any error, `CredentialNotFound` included, refuses execution. The process
    /// environment key is used only when no extension is installed (#1352).
    fn resolve_provider_credential(
        &self,
        context: &AuthenticatedContext,
        provider: &str,
    ) -> Result<ResolvedProviderCredential, ExtensionError> {
        let _ = (context, provider);
        Err(ExtensionError::Unavailable(
            "tenant-scoped provider credentials are not implemented".into(),
        ))
    }

    /// Verify client credentials for a registered service principal and grant
    /// a short-lived tenant-bound token (#1510).
    ///
    /// Default: unavailable. Core looks up the registration first and only
    /// then calls this hook. Implementations must not log or persist
    /// `client_secret`. A successful grant is a service identity, never a
    /// user identity. Core signs and verifies the token with the plane
    /// assertion key from #1507.
    fn issue_service_principal_token(
        &self,
        request: ServicePrincipalTokenRequest,
    ) -> Result<ServicePrincipalTokenGrant, ExtensionError> {
        let _ = request;
        Err(ExtensionError::Unavailable(
            "service-principal token issuance is not implemented".into(),
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
                home_tenant: None,
                tenant: Some(self.tenant_context(&principal)?),
                principal,
                credential_kind: CredentialKind::HumanSession,
                space: None,
                space_role: None,
                act: None,
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
        let auth = extension.authenticate_context("test-token").unwrap();
        assert!(
            extension
                .admit_isolated_process_job(
                    &auth,
                    &IsolatedProcessJob {
                        run_id: "run-1".into(),
                        namespace: "allowed".into(),
                        estimated_seconds: 30,
                    }
                )
                .is_ok()
        );
    }

    #[test]
    fn guest_contexts_fail_closed_unless_the_extension_opts_in() {
        let extension = FakeExtension;
        let member = extension.authenticate_context("test-token").unwrap();
        let guest = AuthenticatedContext {
            home_tenant: Some("tenant-home".into()),
            ..member.clone()
        };
        assert_eq!(member.guest_home_tenant(), None);
        assert_eq!(guest.guest_home_tenant(), Some("tenant-home"));
        // Naming the acting tenant as home is not a guest.
        let own = AuthenticatedContext {
            home_tenant: Some("tenant-test".into()),
            ..member.clone()
        };
        assert_eq!(own.guest_home_tenant(), None);

        // `authorize_namespace` would allow `allowed`; the guest path does not.
        for action in [
            NamespaceAction::Discover,
            NamespaceAction::Read,
            NamespaceAction::Write,
        ] {
            assert!(
                extension
                    .authorize_authenticated_context(&member, "allowed", action)
                    .is_ok()
            );
            assert_eq!(
                extension.authorize_authenticated_context(&guest, "allowed", action),
                Err(ExtensionError::PermissionDenied)
            );
        }
        assert!(member.authorize_space_approval().is_ok());
        assert_eq!(
            guest.authorize_space_approval(),
            Err(ExtensionError::PermissionDenied)
        );

        for malformed in [
            AuthenticatedContext {
                home_tenant: Some(" ".into()),
                ..member.clone()
            },
            AuthenticatedContext {
                tenant: None,
                ..guest.clone()
            },
        ] {
            assert_eq!(
                malformed.authorize_space(NamespaceAction::Discover),
                Err(ExtensionError::PermissionDenied)
            );
        }
    }

    #[test]
    fn shared_space_membership_needs_both_approvals() {
        struct SharedSpaceExtension {
            owner_approved: bool,
            member_approved: bool,
        }

        impl EnterpriseExtension for SharedSpaceExtension {
            fn authenticate_bearer(
                &self,
                bearer_token: &str,
            ) -> Result<AuthenticatedPrincipal, ExtensionError> {
                FakeExtension.authenticate_bearer(bearer_token)
            }

            fn authenticate_context(
                &self,
                bearer_token: &str,
            ) -> Result<AuthenticatedContext, ExtensionError> {
                FakeExtension.authenticate_context(bearer_token)
            }

            fn tenant_context(
                &self,
                principal: &AuthenticatedPrincipal,
            ) -> Result<TenantContext, ExtensionError> {
                FakeExtension.tenant_context(principal)
            }

            fn authorize_namespace(
                &self,
                context: &TenantContext,
                namespace: &str,
                action: NamespaceAction,
            ) -> Result<(), ExtensionError> {
                FakeExtension.authorize_namespace(context, namespace, action)
            }

            fn authorize_unscoped_namespace(
                &self,
                principal: &AuthenticatedPrincipal,
                namespace: &str,
                action: NamespaceAction,
            ) -> Result<(), ExtensionError> {
                FakeExtension.authorize_unscoped_namespace(principal, namespace, action)
            }

            fn authorize_shared_space(
                &self,
                context: &AuthenticatedContext,
                namespace: &str,
                _action: NamespaceAction,
            ) -> Result<SharedSpaceAuthorization, ExtensionError> {
                if context.named_space() != Some("collab") {
                    return Ok(SharedSpaceAuthorization::Unshared);
                }
                if !(self.owner_approved && self.member_approved) {
                    return Ok(SharedSpaceAuthorization::Denied {
                        owner_tenant: "tenant-test".into(),
                    });
                }
                let grant = SharedSpaceGrant {
                    owner_tenant: "tenant-test".into(),
                    namespaces: vec!["ops".into()],
                    kinds: vec!["widget".into()],
                    marking_ceiling: "internal".into(),
                };
                if grant.exposes_namespace(namespace) {
                    Ok(SharedSpaceAuthorization::Granted(grant))
                } else {
                    Ok(SharedSpaceAuthorization::Denied {
                        owner_tenant: grant.owner_tenant,
                    })
                }
            }
        }

        let member = AuthenticatedContext {
            tenant: Some(TenantContext {
                tenant_id: "tenant-home".into(),
                subject: "subject-a".into(),
            }),
            space: Some("collab".into()),
            space_role: Some(SpaceRole::Viewer),
            ..FakeExtension.authenticate_context("test-token").unwrap()
        };
        assert_eq!(member.named_space(), Some("collab"));
        assert_eq!(member.guest_home_tenant(), None);
        assert_eq!(member.home_tenant_id(), Some("tenant-home"));

        for (owner, participant) in [(true, false), (false, true), (false, false)] {
            let extension = SharedSpaceExtension {
                owner_approved: owner,
                member_approved: participant,
            };
            assert_eq!(
                extension.authorize_shared_space(&member, "ops", NamespaceAction::Read),
                Ok(SharedSpaceAuthorization::Denied {
                    owner_tenant: "tenant-test".into(),
                })
            );
            assert_eq!(
                extension.authorize_authenticated_context(&member, "ops", NamespaceAction::Read),
                Err(ExtensionError::PermissionDenied)
            );
        }

        let both = SharedSpaceExtension {
            owner_approved: true,
            member_approved: true,
        };
        let SharedSpaceAuthorization::Granted(grant) = both
            .authorize_shared_space(&member, "ops", NamespaceAction::Read)
            .unwrap()
        else {
            panic!("dual approval exposes ops");
        };
        assert!(grant.exposes_namespace("ops"));
        assert_eq!(
            both.authorize_shared_space(&member, "secrets", NamespaceAction::Read),
            Ok(SharedSpaceAuthorization::Denied {
                owner_tenant: "tenant-test".into(),
            })
        );
        // General namespace authorization must not inherit the grant.
        assert_eq!(
            both.authorize_authenticated_context(&member, "ops", NamespaceAction::Read),
            Err(ExtensionError::PermissionDenied)
        );

        let unshared = AuthenticatedContext {
            space: Some("local".into()),
            space_role: Some(SpaceRole::Viewer),
            ..FakeExtension.authenticate_context("test-token").unwrap()
        };
        assert!(
            both.authorize_authenticated_context(&unshared, "allowed", NamespaceAction::Read)
                .is_ok()
        );
        assert_eq!(
            FakeExtension.authorize_shared_space(&member, "ops", NamespaceAction::Read),
            Ok(SharedSpaceAuthorization::Unshared)
        );
    }

    #[test]
    fn discovery_is_off_until_a_rule_names_the_target() {
        let extension = FakeExtension;
        let guest = AuthenticatedContext {
            home_tenant: Some("tenant-home".into()),
            ..extension.authenticate_context("test-token").unwrap()
        };
        assert_eq!(
            extension.authorize_discovery(&guest, "tenant-test"),
            Ok(None)
        );
        let rule = DiscoveryRule {
            owner_tenant: "tenant-test".into(),
            tenants: vec!["tenant-test".into()],
            principals: vec!["subject-a".into()],
            spaces: vec!["collab".into()],
            namespaces: vec!["ops".into()],
        };
        assert!(rule.exposes_namespace("ops"));
        assert!(!rule.exposes_namespace("secrets"));
        assert!(rule.exposes_tenant("tenant-test"));
        assert!(rule.exposes_principal("subject-a"));
        assert!(rule.exposes_space("collab"));
        assert!(!rule.exposes_space("other"));
    }

    #[test]
    fn community_protocol_has_no_tenant_runtime_methods() {
        let protocol = include_str!("../../../proto/sekai.proto");
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

    #[test]
    fn space_roles_bound_existing_grants_without_changing_unscoped_behavior() {
        let mut context = FakeExtension.authenticate_context("test-token").unwrap();
        assert!(context.authorize_space(NamespaceAction::Write).is_ok());
        assert!(context.authorize_space_approval().is_ok());
        context.space = Some("space-a".into());
        for (role, can_discover, can_read, can_write, can_approve) in [
            (SpaceRole::Discoverer, true, false, false, false),
            (SpaceRole::Viewer, true, true, false, false),
            (SpaceRole::Editor, true, true, true, false),
            (SpaceRole::Approver, true, true, false, true),
            (SpaceRole::Administrator, true, true, true, true),
        ] {
            context.space_role = Some(role);
            assert_eq!(
                context.authorize_space(NamespaceAction::Discover).is_ok(),
                can_discover
            );
            assert_eq!(
                context.authorize_space(NamespaceAction::Read).is_ok(),
                can_read
            );
            assert_eq!(
                context.authorize_space(NamespaceAction::Write).is_ok(),
                can_write
            );
            assert_eq!(context.authorize_space_approval().is_ok(), can_approve);
            assert_eq!(
                FakeExtension
                    .authorize_authenticated_context(&context, "allowed", NamespaceAction::Write)
                    .is_ok(),
                can_write
            );
        }
        context.space_role = None;
        assert!(context.authorize_space(NamespaceAction::Discover).is_err());
        assert!(context.authorize_space(NamespaceAction::Read).is_err());
        context.space = None;
        context.space_role = Some(SpaceRole::Viewer);
        assert!(context.authorize_space(NamespaceAction::Read).is_err());
    }

    #[test]
    fn discover_scope_is_below_read_for_human_sessions() {
        let mut context = FakeExtension.authenticate_context("test-token").unwrap();
        context.space = Some("space-a".into());
        context.space_role = Some(SpaceRole::Discoverer);
        context.scopes = vec!["sekai.discover".into()];
        assert!(
            FakeExtension
                .authorize_authenticated_context(&context, "allowed", NamespaceAction::Discover)
                .is_ok()
        );
        assert_eq!(
            FakeExtension.authorize_authenticated_context(
                &context,
                "allowed",
                NamespaceAction::Read
            ),
            Err(ExtensionError::PermissionDenied)
        );
        assert_eq!(
            FakeExtension.authorize_authenticated_context(
                &context,
                "allowed",
                NamespaceAction::Write
            ),
            Err(ExtensionError::PermissionDenied)
        );
        context.space_role = Some(SpaceRole::Viewer);
        assert_eq!(
            FakeExtension.authorize_authenticated_context(
                &context,
                "allowed",
                NamespaceAction::Read
            ),
            Err(ExtensionError::PermissionDenied)
        );
        context.scopes = vec!["sekai.read".into()];
        assert!(
            FakeExtension
                .authorize_authenticated_context(&context, "allowed", NamespaceAction::Discover)
                .is_ok()
        );
        assert!(
            FakeExtension
                .authorize_authenticated_context(&context, "allowed", NamespaceAction::Read)
                .is_ok()
        );
    }

    #[test]
    fn machine_context_uses_the_full_identity_contract() {
        let context = AuthenticatedContext::machine(AuthenticatedPrincipal {
            subject: "gateway".into(),
            credential_id: "key-1".into(),
        });
        assert_eq!(context.contract_version, IDENTITY_EXTENSION_VERSION);
        assert_eq!(context.credential_kind, CredentialKind::Machine);
        assert_eq!(context.issuer, "sekai:community");
        assert_eq!(context.resource, "sekai:control-plane");
        assert!(context.tenant.is_none());
        assert!(context.scopes.is_empty());
    }

    #[test]
    fn apply_revalidation_fails_closed_for_disabled_member_and_grant() {
        let present = Some("origin-user");
        assert!(
            revalidate_delegating_principal(
                None,
                DelegatingPrincipalState {
                    enabled: false,
                    tenant_member: false,
                    holds_needed_grant: false,
                }
            )
            .is_ok()
        );
        assert!(
            revalidate_delegating_principal(
                Some("  "),
                DelegatingPrincipalState {
                    enabled: false,
                    tenant_member: false,
                    holds_needed_grant: false,
                },
            )
            .is_ok()
        );
        assert_eq!(
            revalidate_delegating_principal(
                present,
                DelegatingPrincipalState {
                    enabled: false,
                    tenant_member: true,
                    holds_needed_grant: true,
                },
            ),
            Err(DelegatorApplyRefusal::Disabled)
        );
        assert_eq!(
            revalidate_delegating_principal(
                present,
                DelegatingPrincipalState {
                    enabled: true,
                    tenant_member: false,
                    holds_needed_grant: false,
                },
            ),
            Err(DelegatorApplyRefusal::NotMember)
        );
        assert_eq!(
            revalidate_delegating_principal(
                present,
                DelegatingPrincipalState {
                    enabled: true,
                    tenant_member: true,
                    holds_needed_grant: false,
                },
            ),
            Err(DelegatorApplyRefusal::GrantMissing)
        );
        assert!(
            revalidate_delegating_principal(
                present,
                DelegatingPrincipalState {
                    enabled: true,
                    tenant_member: true,
                    holds_needed_grant: true,
                },
            )
            .is_ok()
        );
        assert_eq!(DelegatorApplyRefusal::Disabled.as_str(), DELEGATOR_DISABLED);
        assert_eq!(
            DelegatorApplyRefusal::NotMember.as_str(),
            DELEGATOR_NOT_MEMBER
        );
        assert_eq!(
            DelegatorApplyRefusal::GrantMissing.as_str(),
            DELEGATOR_GRANT_MISSING
        );
        assert_eq!(
            DelegatorApplyRefusal::RecordMissing.as_str(),
            DELEGATOR_RECORD_MISSING
        );
    }

    #[test]
    fn resolved_provider_credential_debug_redacts_secret() {
        let credential = ResolvedProviderCredential {
            credential_id: "cred-1".into(),
            tenant_id: Some("tenant-a".into()),
            provider: "openai".into(),
            generation: 3,
            secret: SecretValue::new("sk-live-secret"),
        };
        let rendered = format!("{credential:?}");
        assert!(rendered.contains("cred-1"));
        assert!(rendered.contains("[REDACTED]"));
        assert!(!rendered.contains("sk-live-secret"));
    }

    #[test]
    fn service_principal_issuance_defaults_unavailable_and_redacts_secret() {
        let request = ServicePrincipalTokenRequest {
            principal: "worker-a".into(),
            client_secret: SecretValue::new("client-secret"),
            tenant_id: "tenant-a".into(),
            namespaces: vec!["ns-a".into()],
            action_types: vec!["dispatch".into()],
        };
        let rendered = format!("{request:?}");
        assert!(rendered.contains("worker-a"));
        assert!(rendered.contains("[REDACTED]"));
        assert!(!rendered.contains("client-secret"));
        assert!(matches!(
            FakeExtension.issue_service_principal_token(request),
            Err(ExtensionError::Unavailable(_))
        ));
    }
}
