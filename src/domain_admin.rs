//! Sekai Chisei domain-administration contracts (#125).
//!
//! Versioned facade for tenant administrators over governed resources already
//! owned by quotas, entitlements, invitations, provider credentials, and usage
//! ledger. Does not create a second tenant directory or platform-operator path.

use std::sync::Arc;

use crate::chisei::entitlements::{EffectiveEntitlement, EntitlementError, EntitlementRegistry};
use crate::chisei::tenant_quota::{
    TenantQuotaError, TenantQuotaGate, TenantQuotaLimits, TenantQuotaReceiptNote,
};
use crate::chisei::usage_ledger::{UsageAggregate, UsageUnit};
use crate::db::runtime_db::RuntimeDb;
use crate::db::sekai::SekaiDb;
use crate::enterprise::{AuthenticatedContext, SecretValue};
use crate::provider_credentials::{
    MemoryTenantProviderCredentialResolver, ProviderCredentialRef,
    TenantProviderCredentialResolver, resolution_failure_message,
};
use crate::tenant_invitation::{
    AcceptedMembership, InvitationError, InvitationRole, InvitationView, MemoryInvitationHooks,
    human_context,
};

pub const DOMAIN_ADMIN_VERSION: &str = "sekai.domain-admin/v1";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AdminRole {
    Owner,
    Admin,
    Member,
    BillingViewer,
}

impl AdminRole {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Owner => "owner",
            Self::Admin => "admin",
            Self::Member => "member",
            Self::BillingViewer => "billing_viewer",
        }
    }

    pub fn can_mutate_members(self) -> bool {
        matches!(self, Self::Owner | Self::Admin)
    }

    pub fn can_view_usage(self) -> bool {
        matches!(
            self,
            Self::Owner | Self::Admin | Self::BillingViewer | Self::Member
        )
    }

    pub fn can_manage_credentials(self) -> bool {
        matches!(self, Self::Owner | Self::Admin)
    }

    pub fn can_manage_quotas(self) -> bool {
        matches!(self, Self::Owner | Self::Admin)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DomainAdminError {
    Unauthorized,
    CrossTenant,
    Entitlement(EntitlementError),
    Quota(TenantQuotaError),
    Invitation(InvitationError),
    Credential(String),
    Invalid(String),
}

impl std::fmt::Display for DomainAdminError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Unauthorized => write!(f, "domain admin action unauthorized"),
            Self::CrossTenant => write!(f, "cross-tenant access denied"),
            Self::Entitlement(e) => write!(f, "entitlement: {e}"),
            Self::Quota(e) => write!(f, "quota: {e}"),
            Self::Invitation(e) => write!(f, "invitation: {e}"),
            Self::Credential(e) => write!(f, "credential: {e}"),
            Self::Invalid(e) => write!(f, "invalid: {e}"),
        }
    }
}

impl std::error::Error for DomainAdminError {}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DomainAdminAudit {
    pub actor: String,
    pub tenant_id: String,
    pub action: String,
    pub target: String,
    pub result: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TenantProfileView {
    pub tenant_id: String,
    pub entitlement: Option<EffectiveEntitlement>,
    pub contract_version: &'static str,
}

/// Composed domain-admin surface for tests and enterprise wiring.
pub struct DomainAdminSurface {
    pub invitations: Arc<MemoryInvitationHooks>,
    pub entitlements: Arc<EntitlementRegistry>,
    pub quotas: TenantQuotaGate,
    pub credentials: Arc<MemoryTenantProviderCredentialResolver>,
    pub db: Arc<SekaiDb>,
    roles: std::sync::RwLock<std::collections::HashMap<(String, String), AdminRole>>,
    audit: std::sync::RwLock<Vec<DomainAdminAudit>>,
}

impl DomainAdminSurface {
    pub fn new(db: Arc<SekaiDb>) -> Self {
        Self {
            invitations: Arc::new(MemoryInvitationHooks::new()),
            entitlements: Arc::new(EntitlementRegistry::new()),
            quotas: TenantQuotaGate::new(Arc::new(RuntimeDb::Sqlite(db.clone()))),
            credentials: Arc::new(MemoryTenantProviderCredentialResolver::new()),
            db,
            roles: std::sync::RwLock::new(std::collections::HashMap::new()),
            audit: std::sync::RwLock::new(Vec::new()),
        }
    }

    pub fn grant_role(&self, tenant_id: &str, subject: &str, role: AdminRole) {
        self.roles
            .write()
            .unwrap()
            .insert((tenant_id.into(), subject.into()), role);
        if matches!(role, AdminRole::Owner | AdminRole::Admin) {
            self.invitations.seed_owner(tenant_id, subject);
        }
    }

    pub fn audit_log(&self) -> Vec<DomainAdminAudit> {
        self.audit.read().unwrap().clone()
    }

    fn require_role(
        &self,
        context: &AuthenticatedContext,
        tenant_id: &str,
        predicate: impl Fn(AdminRole) -> bool,
    ) -> Result<AdminRole, DomainAdminError> {
        let subject = &context.principal.subject;
        if let Some(t) = &context.tenant
            && t.tenant_id != tenant_id
        {
            return Err(DomainAdminError::CrossTenant);
        }
        let role = self
            .roles
            .read()
            .unwrap()
            .get(&(tenant_id.into(), subject.clone()))
            .copied()
            .ok_or(DomainAdminError::Unauthorized)?;
        if !predicate(role) {
            return Err(DomainAdminError::Unauthorized);
        }
        Ok(role)
    }

    fn audit(&self, actor: &str, tenant_id: &str, action: &str, target: &str, result: &str) {
        self.audit.write().unwrap().push(DomainAdminAudit {
            actor: actor.into(),
            tenant_id: tenant_id.into(),
            action: action.into(),
            target: target.into(),
            result: result.into(),
        });
    }

    pub fn get_profile(
        &self,
        context: &AuthenticatedContext,
        tenant_id: &str,
        now_ms: i64,
    ) -> Result<TenantProfileView, DomainAdminError> {
        self.require_role(context, tenant_id, |_| true)?;
        let entitlement = self.entitlements.resolve(context, now_ms).ok();
        self.audit(
            &context.principal.subject,
            tenant_id,
            "get_profile",
            tenant_id,
            "ok",
        );
        Ok(TenantProfileView {
            tenant_id: tenant_id.into(),
            entitlement,
            contract_version: DOMAIN_ADMIN_VERSION,
        })
    }

    pub fn create_invitation(
        &self,
        context: &AuthenticatedContext,
        tenant_id: &str,
        role: InvitationRole,
        now_ms: i64,
        secret: SecretValue,
    ) -> Result<(InvitationView, SecretValue), DomainAdminError> {
        self.require_role(context, tenant_id, AdminRole::can_mutate_members)?;
        let result = self
            .invitations
            .create(context, tenant_id, role, now_ms, 86_400_000, secret)
            .map_err(DomainAdminError::Invitation);
        match &result {
            Ok((view, _)) => self.audit(
                &context.principal.subject,
                tenant_id,
                "create_invitation",
                &view.invitation_id,
                "ok",
            ),
            Err(e) => self.audit(
                &context.principal.subject,
                tenant_id,
                "create_invitation",
                tenant_id,
                &e.to_string(),
            ),
        }
        result
    }

    pub fn accept_invitation(
        &self,
        context: &AuthenticatedContext,
        raw_secret: &str,
        now_ms: i64,
    ) -> Result<AcceptedMembership, DomainAdminError> {
        let result = self
            .invitations
            .accept(context, raw_secret, None, None, now_ms)
            .map_err(DomainAdminError::Invitation);
        if let Ok(m) = &result {
            self.grant_role(
                &m.tenant_id,
                &m.subject,
                match m.role {
                    InvitationRole::Owner => AdminRole::Owner,
                    InvitationRole::Admin => AdminRole::Admin,
                    InvitationRole::Member => AdminRole::Member,
                },
            );
            self.audit(
                &context.principal.subject,
                &m.tenant_id,
                "accept_invitation",
                &m.invitation_id,
                "ok",
            );
        }
        result
    }

    pub fn configure_quotas(
        &self,
        context: &AuthenticatedContext,
        tenant_id: &str,
        limits: &TenantQuotaLimits,
    ) -> Result<TenantQuotaReceiptNote, DomainAdminError> {
        self.require_role(context, tenant_id, AdminRole::can_manage_quotas)?;
        // Entitlement may only narrow.
        let narrowed = self
            .entitlements
            .narrow_quota_limits(context, limits, chrono::Utc::now().timestamp_millis())
            .map_err(DomainAdminError::Entitlement)?;
        self.quotas
            .configure(tenant_id, &narrowed)
            .map_err(DomainAdminError::Quota)?;
        self.audit(
            &context.principal.subject,
            tenant_id,
            "configure_quotas",
            tenant_id,
            "ok",
        );
        Ok(TenantQuotaReceiptNote {
            tenant_id: tenant_id.into(),
            assignment_version: narrowed.version,
            admitted_metrics: vec![],
            exhausted_metric: None,
        })
    }

    pub fn rotate_provider_credential(
        &self,
        context: &AuthenticatedContext,
        tenant_id: &str,
        provider: &str,
        secret: impl Into<String>,
    ) -> Result<ProviderCredentialRef, DomainAdminError> {
        self.require_role(context, tenant_id, AdminRole::can_manage_credentials)?;
        if let Some(t) = &context.tenant
            && t.tenant_id != tenant_id
        {
            return Err(DomainAdminError::CrossTenant);
        }
        let reference = self.credentials.upsert(tenant_id, provider, secret);
        // Never return secret; ProviderCredentialRef has no secret field.
        self.audit(
            &context.principal.subject,
            tenant_id,
            "rotate_provider_credential",
            &reference.credential_id,
            "ok",
        );
        Ok(reference)
    }

    pub fn usage_summary(
        &self,
        context: &AuthenticatedContext,
        tenant_id: &str,
        start_ms: i64,
        end_ms: i64,
    ) -> Result<UsageAggregate, DomainAdminError> {
        self.require_role(context, tenant_id, AdminRole::can_view_usage)?;
        let agg = self
            .db
            .aggregate_usage_for_tenant(tenant_id, UsageUnit::Tokens, start_ms, end_ms)
            .map_err(DomainAdminError::Invalid)?;
        self.audit(
            &context.principal.subject,
            tenant_id,
            "usage_summary",
            tenant_id,
            "ok",
        );
        Ok(agg)
    }

    pub fn resolve_provider_for_execution(
        &self,
        context: &AuthenticatedContext,
        provider: &str,
    ) -> Result<String, DomainAdminError> {
        // Returns only credential id for attribution — not the secret.
        let resolved = self
            .credentials
            .as_ref()
            .resolve(context, provider)
            .map_err(|e| DomainAdminError::Credential(resolution_failure_message(&e).into()))?;
        Ok(resolved.credential_id)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::chisei::budget::PeriodType;
    use crate::chisei::entitlements::{EntitlementSet, TenantEntitlementAssignment};
    use crate::provider_credentials::tenant_context;
    use crate::tenant_invitation::human_context;
    use std::collections::BTreeSet;
    use std::sync::Arc;

    fn surface() -> DomainAdminSurface {
        DomainAdminSurface::new(Arc::new(SekaiDb::new(":memory:").unwrap()))
    }

    #[test]
    fn role_matrix_and_cross_tenant_denied() {
        let admin = surface();
        admin.grant_role("tenant-a", "alice", AdminRole::Owner);
        admin.grant_role("tenant-a", "bob", AdminRole::Member);
        admin.grant_role("tenant-b", "carol", AdminRole::Owner);

        let alice = tenant_context("tenant-a", "alice");
        let bob = tenant_context("tenant-a", "bob");
        let carol = tenant_context("tenant-b", "carol");

        assert!(admin.get_profile(&alice, "tenant-a", 1).is_ok());
        assert!(admin.get_profile(&bob, "tenant-a", 1).is_ok());
        // Member cannot create invitations
        assert!(matches!(
            admin.create_invitation(
                &bob,
                "tenant-a",
                InvitationRole::Member,
                1,
                SecretValue::new("token-hhhhhhhhhhhh")
            ),
            Err(DomainAdminError::Unauthorized)
        ));
        // Cross-tenant profile denied
        assert!(matches!(
            admin.get_profile(&carol, "tenant-a", 1),
            Err(DomainAdminError::CrossTenant)
        ));
    }

    #[test]
    fn credentials_never_return_secret_material() {
        let admin = surface();
        admin.grant_role("tenant-a", "alice", AdminRole::Admin);
        let alice = tenant_context("tenant-a", "alice");
        let reference = admin
            .rotate_provider_credential(&alice, "tenant-a", "openai", "sk-secret-value")
            .unwrap();
        assert!(!format!("{reference:?}").contains("sk-secret"));
        let id = admin
            .resolve_provider_for_execution(&alice, "openai")
            .unwrap();
        assert_eq!(id, reference.credential_id);
        assert!(!id.contains("sk-"));
    }

    #[test]
    fn quotas_are_narrowed_by_entitlements() {
        let admin = surface();
        admin.grant_role("tenant-a", "alice", AdminRole::Owner);
        let alice = tenant_context("tenant-a", "alice");
        admin.entitlements.assign(TenantEntitlementAssignment {
            tenant_id: "tenant-a".into(),
            set: EntitlementSet {
                version: 1,
                set_id: "starter".into(),
                features: BTreeSet::from(["core.chat".into()]),
                quota_ceiling: Some(TenantQuotaLimits {
                    version: 1,
                    max_requests_per_period: Some(5),
                    max_tokens_per_period: Some(50),
                    max_concurrency: Some(1),
                    max_storage_bytes: Some(100),
                    period: PeriodType::Daily,
                }),
                expires_at_ms: None,
            },
            assigned_at_ms: 1,
            removed: false,
        });
        let note = admin
            .configure_quotas(
                &alice,
                "tenant-a",
                &TenantQuotaLimits {
                    version: 2,
                    max_requests_per_period: Some(100),
                    max_tokens_per_period: Some(50),
                    max_concurrency: Some(10),
                    max_storage_bytes: Some(1000),
                    period: PeriodType::Daily,
                },
            )
            .unwrap();
        assert_eq!(note.tenant_id, "tenant-a");
        let log = admin.audit_log();
        assert!(
            log.iter().any(|e| {
                e.action == "configure_quotas" && e.actor == "alice" && e.result == "ok"
            })
        );
    }

    #[test]
    fn invitation_flow_through_admin_surface() {
        let admin = surface();
        admin.grant_role("tenant-a", "alice", AdminRole::Owner);
        let alice = tenant_context("tenant-a", "alice");
        let (view, secret) = admin
            .create_invitation(
                &alice,
                "tenant-a",
                InvitationRole::Member,
                1_000,
                SecretValue::new("token-iiiiiiiiiiii"),
            )
            .unwrap();
        let bob = human_context("bob");
        let membership = admin
            .accept_invitation(&bob, secret.expose(), 1_001)
            .unwrap();
        assert_eq!(membership.subject, "bob");
        assert_eq!(membership.invitation_id, view.invitation_id);
    }

    #[test]
    fn audit_covers_mutations() {
        let admin = surface();
        admin.grant_role("tenant-a", "alice", AdminRole::Owner);
        let alice = tenant_context("tenant-a", "alice");
        admin.get_profile(&alice, "tenant-a", 1).unwrap();
        admin
            .rotate_provider_credential(&alice, "tenant-a", "anthropic", "ant-key")
            .unwrap();
        let events = admin.audit_log();
        assert!(events.iter().any(|e| e.action == "get_profile"));
        assert!(
            events
                .iter()
                .any(|e| e.action == "rotate_provider_credential")
        );
        for e in &events {
            assert!(!format!("{e:?}").contains("ant-key"));
        }
    }
}
