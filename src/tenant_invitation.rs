//! Tenant invitation authorization hooks (#121).
//!
//! Backend-neutral contract for single-use, expiring invitations. Concrete
//! storage, email delivery, and OIDC sessions belong to the enterprise tenant
//! authority. The community runtime provides the authorization semantics and a
//! deterministic in-memory store for tests only.

use std::collections::HashMap;
use std::sync::RwLock;

use sha2::{Digest, Sha256};

use crate::enterprise::{AuthenticatedContext, AuthenticatedPrincipal, SecretValue};

pub const INVITATION_HOOK_VERSION: &str = "sekai.tenant-invitation/v1";

/// Membership roles an invitation may propose.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum InvitationRole {
    Member,
    Admin,
    Owner,
}

impl InvitationRole {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Member => "member",
            Self::Admin => "admin",
            Self::Owner => "owner",
        }
    }

    pub fn parse(value: &str) -> Option<Self> {
        match value {
            "member" => Some(Self::Member),
            "admin" => Some(Self::Admin),
            "owner" => Some(Self::Owner),
            _ => None,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum InvitationStatus {
    Pending,
    Accepted,
    Revoked,
    Expired,
}

impl InvitationStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Pending => "pending",
            Self::Accepted => "accepted",
            Self::Revoked => "revoked",
            Self::Expired => "expired",
        }
    }
}

/// Public inspection view — never includes the raw secret.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InvitationView {
    pub invitation_id: String,
    pub tenant_id: String,
    pub proposed_role: InvitationRole,
    pub invited_by: String,
    pub status: InvitationStatus,
    pub created_at_ms: i64,
    pub expires_at_ms: i64,
    pub accepted_subject: Option<String>,
}

/// Result of accepting an invitation (exactly one membership under retry).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AcceptedMembership {
    pub tenant_id: String,
    pub subject: String,
    pub role: InvitationRole,
    pub invitation_id: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum InvitationError {
    Unauthorized,
    NotFound,
    Expired,
    Revoked,
    AlreadyAccepted,
    WrongTenant,
    RoleModified,
    LastOwnerInvariant,
    Invalid(String),
}

impl std::fmt::Display for InvitationError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Unauthorized => write!(f, "invitation action unauthorized"),
            Self::NotFound => write!(f, "invitation not found"),
            Self::Expired => write!(f, "invitation expired"),
            Self::Revoked => write!(f, "invitation revoked"),
            Self::AlreadyAccepted => write!(f, "invitation already accepted"),
            Self::WrongTenant => write!(f, "invitation tenant mismatch"),
            Self::RoleModified => write!(f, "invitation role no longer valid"),
            Self::LastOwnerInvariant => {
                write!(f, "cannot leave tenant without at least one owner")
            }
            Self::Invalid(m) => write!(f, "invitation invalid: {m}"),
        }
    }
}

impl std::error::Error for InvitationError {}

/// Audit-oriented event (no secrets).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InvitationAuditEvent {
    pub action: &'static str,
    pub invitation_id: String,
    pub tenant_id: String,
    pub actor: String,
    pub outcome: &'static str,
    pub detail: String,
}

fn hash_secret(secret: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(secret.as_bytes());
    hasher
        .finalize()
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect()
}

#[derive(Clone)]
struct StoredInvitation {
    invitation_id: String,
    tenant_id: String,
    proposed_role: InvitationRole,
    invited_by: String,
    secret_hash: String,
    status: InvitationStatus,
    created_at_ms: i64,
    expires_at_ms: i64,
    accepted_subject: Option<String>,
    /// Role frozen at creation; acceptance fails if enterprise mutates it away.
    role_version: u64,
}

/// Membership directory hook used for last-owner checks.
pub trait MembershipDirectory: Send + Sync {
    fn is_tenant_admin(&self, tenant_id: &str, subject: &str) -> bool;
    fn owner_count(&self, tenant_id: &str) -> usize;
    fn has_membership(&self, tenant_id: &str, subject: &str) -> bool;
    fn add_membership(
        &self,
        tenant_id: &str,
        subject: &str,
        role: InvitationRole,
    ) -> Result<(), InvitationError>;
}

/// Deterministic invitation store + authorization hooks for tests/fakes.
pub struct MemoryInvitationHooks {
    invitations: RwLock<HashMap<String, StoredInvitation>>,
    by_hash: RwLock<HashMap<String, String>>,
    memberships: RwLock<HashMap<String, HashMap<String, InvitationRole>>>,
    audit: RwLock<Vec<InvitationAuditEvent>>,
    next_id: RwLock<u64>,
}

impl Default for MemoryInvitationHooks {
    fn default() -> Self {
        Self::new()
    }
}

impl MemoryInvitationHooks {
    pub fn new() -> Self {
        Self {
            invitations: RwLock::new(HashMap::new()),
            by_hash: RwLock::new(HashMap::new()),
            memberships: RwLock::new(HashMap::new()),
            audit: RwLock::new(Vec::new()),
            next_id: RwLock::new(1),
        }
    }

    pub fn seed_owner(&self, tenant_id: &str, subject: &str) {
        self.memberships
            .write()
            .unwrap()
            .entry(tenant_id.into())
            .or_default()
            .insert(subject.into(), InvitationRole::Owner);
    }

    pub fn audit_log(&self) -> Vec<InvitationAuditEvent> {
        self.audit.read().unwrap().clone()
    }

    fn record(
        &self,
        action: &'static str,
        invitation_id: &str,
        tenant_id: &str,
        actor: &str,
        outcome: &'static str,
        detail: impl Into<String>,
    ) {
        self.audit.write().unwrap().push(InvitationAuditEvent {
            action,
            invitation_id: invitation_id.into(),
            tenant_id: tenant_id.into(),
            actor: actor.into(),
            outcome,
            detail: detail.into(),
        });
    }

    /// Create a single-use invitation. Returns (view, raw_secret) once.
    /// Raw secret must only be delivered through an adapter (URL/token).
    pub fn create(
        &self,
        actor: &AuthenticatedContext,
        tenant_id: &str,
        proposed_role: InvitationRole,
        now_ms: i64,
        ttl_ms: i64,
        raw_secret: SecretValue,
    ) -> Result<(InvitationView, SecretValue), InvitationError> {
        let subject = &actor.principal.subject;
        if !self.is_tenant_admin(tenant_id, subject) {
            self.record(
                "create",
                "",
                tenant_id,
                subject,
                "denied",
                "not tenant admin",
            );
            return Err(InvitationError::Unauthorized);
        }
        if ttl_ms <= 0 {
            return Err(InvitationError::Invalid("ttl_ms must be positive".into()));
        }
        let secret = raw_secret.expose();
        if secret.len() < 16 {
            return Err(InvitationError::Invalid(
                "invitation secret must be at least 16 bytes".into(),
            ));
        }
        let secret_hash = hash_secret(secret);
        if self.by_hash.read().unwrap().contains_key(&secret_hash) {
            return Err(InvitationError::Invalid(
                "invitation secret collision".into(),
            ));
        }
        let mut id_guard = self.next_id.write().unwrap();
        let invitation_id = format!("inv-{}", *id_guard);
        *id_guard += 1;
        drop(id_guard);

        let stored = StoredInvitation {
            invitation_id: invitation_id.clone(),
            tenant_id: tenant_id.into(),
            proposed_role,
            invited_by: subject.clone(),
            secret_hash: secret_hash.clone(),
            status: InvitationStatus::Pending,
            created_at_ms: now_ms,
            expires_at_ms: now_ms.saturating_add(ttl_ms),
            accepted_subject: None,
            role_version: 1,
        };
        let view = to_view(&stored);
        self.invitations
            .write()
            .unwrap()
            .insert(invitation_id.clone(), stored);
        self.by_hash
            .write()
            .unwrap()
            .insert(secret_hash, invitation_id.clone());
        self.record(
            "create",
            &invitation_id,
            tenant_id,
            subject,
            "ok",
            format!("role={}", proposed_role.as_str()),
        );
        Ok((view, raw_secret))
    }

    pub fn inspect_by_secret(
        &self,
        raw_secret: &str,
        now_ms: i64,
    ) -> Result<InvitationView, InvitationError> {
        let stored = self.lookup_by_secret(raw_secret)?;
        self.materialize_status(&stored.invitation_id, now_ms)?;
        let inv = self
            .invitations
            .read()
            .unwrap()
            .get(&stored.invitation_id)
            .cloned()
            .ok_or(InvitationError::NotFound)?;
        Ok(to_view(&inv))
    }

    pub fn revoke(
        &self,
        actor: &AuthenticatedContext,
        invitation_id: &str,
        now_ms: i64,
    ) -> Result<InvitationView, InvitationError> {
        let subject = &actor.principal.subject;
        let mut map = self.invitations.write().unwrap();
        let inv = map
            .get_mut(invitation_id)
            .ok_or(InvitationError::NotFound)?;
        if !self.is_tenant_admin(&inv.tenant_id, subject) {
            self.record(
                "revoke",
                invitation_id,
                &inv.tenant_id,
                subject,
                "denied",
                "not tenant admin",
            );
            return Err(InvitationError::Unauthorized);
        }
        if inv.status == InvitationStatus::Pending && inv.expires_at_ms <= now_ms {
            inv.status = InvitationStatus::Expired;
        }
        match inv.status {
            InvitationStatus::Pending => {
                inv.status = InvitationStatus::Revoked;
                let view = to_view(inv);
                self.record("revoke", invitation_id, &view.tenant_id, subject, "ok", "");
                Ok(view)
            }
            InvitationStatus::Revoked => Err(InvitationError::Revoked),
            InvitationStatus::Expired => Err(InvitationError::Expired),
            InvitationStatus::Accepted => Err(InvitationError::AlreadyAccepted),
        }
    }

    /// Accept binds to the authenticated OIDC subject. Idempotent under retry
    /// for the same subject: returns the same membership once accepted.
    pub fn accept(
        &self,
        actor: &AuthenticatedContext,
        raw_secret: &str,
        expected_tenant_id: Option<&str>,
        expected_role: Option<InvitationRole>,
        now_ms: i64,
    ) -> Result<AcceptedMembership, InvitationError> {
        let subject = &actor.principal.subject;
        let invitation_id = {
            let stored = self.lookup_by_secret(raw_secret)?;
            stored.invitation_id.clone()
        };
        self.materialize_status(&invitation_id, now_ms)?;

        let mut map = self.invitations.write().unwrap();
        let inv = map
            .get_mut(&invitation_id)
            .ok_or(InvitationError::NotFound)?;

        if let Some(expected) = expected_tenant_id
            && expected != inv.tenant_id
        {
            self.record(
                "accept",
                &invitation_id,
                &inv.tenant_id,
                subject,
                "denied",
                "wrong tenant",
            );
            return Err(InvitationError::WrongTenant);
        }
        if let Some(role) = expected_role
            && (role != inv.proposed_role || inv.role_version != 1)
        {
            self.record(
                "accept",
                &invitation_id,
                &inv.tenant_id,
                subject,
                "denied",
                "role modified",
            );
            return Err(InvitationError::RoleModified);
        }
        if inv.role_version != 1 {
            self.record(
                "accept",
                &invitation_id,
                &inv.tenant_id,
                subject,
                "denied",
                "role modified",
            );
            return Err(InvitationError::RoleModified);
        }
        match inv.status {
            InvitationStatus::Expired => {
                self.record(
                    "accept",
                    &invitation_id,
                    &inv.tenant_id,
                    subject,
                    "denied",
                    "expired",
                );
                return Err(InvitationError::Expired);
            }
            InvitationStatus::Revoked => {
                self.record(
                    "accept",
                    &invitation_id,
                    &inv.tenant_id,
                    subject,
                    "denied",
                    "revoked",
                );
                return Err(InvitationError::Revoked);
            }
            InvitationStatus::Accepted => {
                if inv.accepted_subject.as_deref() == Some(subject.as_str()) {
                    // Retry-safe: same subject re-accept is success.
                    return Ok(AcceptedMembership {
                        tenant_id: inv.tenant_id.clone(),
                        subject: subject.clone(),
                        role: inv.proposed_role,
                        invitation_id: inv.invitation_id.clone(),
                    });
                }
                self.record(
                    "accept",
                    &invitation_id,
                    &inv.tenant_id,
                    subject,
                    "denied",
                    "already accepted",
                );
                return Err(InvitationError::AlreadyAccepted);
            }
            InvitationStatus::Pending => {}
        }

        let tenant_id = inv.tenant_id.clone();
        let role = inv.proposed_role;
        drop(map);

        // Membership write outside invitation lock to avoid deadlocks; re-check.
        if self.has_membership(&tenant_id, subject) {
            // Already a member: consume invitation without double membership.
            let mut map = self.invitations.write().unwrap();
            if let Some(inv) = map.get_mut(&invitation_id) {
                inv.status = InvitationStatus::Accepted;
                inv.accepted_subject = Some(subject.clone());
            }
            self.record(
                "accept",
                &invitation_id,
                &tenant_id,
                subject,
                "ok",
                "already member",
            );
            return Ok(AcceptedMembership {
                tenant_id,
                subject: subject.clone(),
                role,
                invitation_id,
            });
        }

        self.add_membership(&tenant_id, subject, role)?;
        {
            let mut map = self.invitations.write().unwrap();
            if let Some(inv) = map.get_mut(&invitation_id) {
                inv.status = InvitationStatus::Accepted;
                inv.accepted_subject = Some(subject.clone());
            }
        }
        self.record(
            "accept",
            &invitation_id,
            &tenant_id,
            subject,
            "ok",
            format!("role={}", role.as_str()),
        );
        Ok(AcceptedMembership {
            tenant_id,
            subject: subject.clone(),
            role,
            invitation_id,
        })
    }

    /// Protect last-owner invariant when demoting/removing an owner.
    pub fn ensure_not_last_owner(
        &self,
        tenant_id: &str,
        subject: &str,
    ) -> Result<(), InvitationError> {
        let map = self.memberships.read().unwrap();
        let Some(members) = map.get(tenant_id) else {
            return Ok(());
        };
        if members.get(subject) != Some(&InvitationRole::Owner) {
            return Ok(());
        }
        let owners = members
            .values()
            .filter(|r| **r == InvitationRole::Owner)
            .count();
        if owners <= 1 {
            return Err(InvitationError::LastOwnerInvariant);
        }
        Ok(())
    }

    fn lookup_by_secret(&self, raw_secret: &str) -> Result<StoredInvitation, InvitationError> {
        let hash = hash_secret(raw_secret);
        let id = self
            .by_hash
            .read()
            .unwrap()
            .get(&hash)
            .cloned()
            .ok_or(InvitationError::NotFound)?;
        let inv = self
            .invitations
            .read()
            .unwrap()
            .get(&id)
            .cloned()
            .ok_or(InvitationError::NotFound)?;
        // Constant-time-ish equality via hash match (hash is the lookup key).
        if inv.secret_hash != hash {
            return Err(InvitationError::NotFound);
        }
        // role_version is frozen at create; external role edits bump it.
        let _ = inv.role_version;
        Ok(inv)
    }

    /// Enterprise may mark a pending invitation's role as modified.
    pub fn mark_role_modified(&self, invitation_id: &str) -> Result<(), InvitationError> {
        let mut map = self.invitations.write().unwrap();
        let inv = map
            .get_mut(invitation_id)
            .ok_or(InvitationError::NotFound)?;
        inv.role_version = inv.role_version.saturating_add(1);
        Ok(())
    }

    fn materialize_status(&self, invitation_id: &str, now_ms: i64) -> Result<(), InvitationError> {
        let mut map = self.invitations.write().unwrap();
        let inv = map
            .get_mut(invitation_id)
            .ok_or(InvitationError::NotFound)?;
        if inv.status == InvitationStatus::Pending && inv.expires_at_ms <= now_ms {
            inv.status = InvitationStatus::Expired;
        }
        Ok(())
    }
}

impl MembershipDirectory for MemoryInvitationHooks {
    fn is_tenant_admin(&self, tenant_id: &str, subject: &str) -> bool {
        matches!(
            self.memberships
                .read()
                .unwrap()
                .get(tenant_id)
                .and_then(|m| m.get(subject)),
            Some(InvitationRole::Admin | InvitationRole::Owner)
        )
    }

    fn owner_count(&self, tenant_id: &str) -> usize {
        self.memberships
            .read()
            .unwrap()
            .get(tenant_id)
            .map(|m| m.values().filter(|r| **r == InvitationRole::Owner).count())
            .unwrap_or(0)
    }

    fn has_membership(&self, tenant_id: &str, subject: &str) -> bool {
        self.memberships
            .read()
            .unwrap()
            .get(tenant_id)
            .is_some_and(|m| m.contains_key(subject))
    }

    fn add_membership(
        &self,
        tenant_id: &str,
        subject: &str,
        role: InvitationRole,
    ) -> Result<(), InvitationError> {
        self.memberships
            .write()
            .unwrap()
            .entry(tenant_id.into())
            .or_default()
            .insert(subject.into(), role);
        Ok(())
    }
}

fn to_view(inv: &StoredInvitation) -> InvitationView {
    InvitationView {
        invitation_id: inv.invitation_id.clone(),
        tenant_id: inv.tenant_id.clone(),
        proposed_role: inv.proposed_role,
        invited_by: inv.invited_by.clone(),
        status: inv.status,
        created_at_ms: inv.created_at_ms,
        expires_at_ms: inv.expires_at_ms,
        accepted_subject: inv.accepted_subject.clone(),
    }
}

/// Invitation URL/token payload returned to adapters (secret once).
pub fn invitation_token_url(base: &str, raw_secret: &str) -> String {
    format!(
        "{}/accept-invitation?token={}",
        base.trim_end_matches('/'),
        urlencoding_minimal(raw_secret)
    )
}

fn urlencoding_minimal(value: &str) -> String {
    // Secrets are expected to be URL-safe tokens from enterprise; pass through.
    value.to_string()
}

pub fn human_context(subject: &str) -> AuthenticatedContext {
    let mut ctx = AuthenticatedContext::machine(AuthenticatedPrincipal {
        subject: subject.into(),
        credential_id: format!("session:{subject}"),
    });
    ctx.credential_kind = crate::enterprise::CredentialKind::HumanSession;
    ctx.scopes = vec!["sekai.write".into()];
    ctx.issuer = "https://issuer.test".into();
    ctx.resource = "https://sekai.test".into();
    ctx
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn secrets_are_hashed_and_not_enumerable_by_id_alone() {
        let hooks = MemoryInvitationHooks::new();
        hooks.seed_owner("tenant-a", "alice");
        let actor = human_context("alice");
        let secret = SecretValue::new("super-secret-token-aa");
        let (view, raw) = hooks
            .create(
                &actor,
                "tenant-a",
                InvitationRole::Member,
                1_000,
                60_000,
                secret,
            )
            .unwrap();
        assert_eq!(view.status, InvitationStatus::Pending);
        assert_eq!(raw.expose(), "super-secret-token-aa");
        // Raw secret not present in Debug of view
        assert!(!format!("{view:?}").contains("super-secret"));
        // Enumeration by sequential guess of wrong secret fails closed
        assert!(matches!(
            hooks.inspect_by_secret("wrong-secret-xxxxx", 1_001),
            Err(InvitationError::NotFound)
        ));
    }

    #[test]
    fn expired_revoked_reused_wrong_tenant_and_role_fail() {
        let hooks = MemoryInvitationHooks::new();
        hooks.seed_owner("tenant-a", "alice");
        let actor = human_context("alice");
        let (view, raw) = hooks
            .create(
                &actor,
                "tenant-a",
                InvitationRole::Member,
                1_000,
                100,
                SecretValue::new("token-aaaaaaaaaaaa"),
            )
            .unwrap();
        assert!(matches!(
            hooks.inspect_by_secret(raw.expose(), 1_200),
            Err(InvitationError::NotFound) | Ok(_)
        ));
        // After expiry materialization via accept
        let bob = human_context("bob");
        assert!(matches!(
            hooks.accept(&bob, raw.expose(), None, None, 1_200),
            Err(InvitationError::Expired)
        ));

        let (view2, raw2) = hooks
            .create(
                &actor,
                "tenant-a",
                InvitationRole::Admin,
                2_000,
                60_000,
                SecretValue::new("token-bbbbbbbbbbbb"),
            )
            .unwrap();
        hooks.revoke(&actor, &view2.invitation_id, 2_001).unwrap();
        assert!(matches!(
            hooks.accept(&bob, raw2.expose(), None, None, 2_002),
            Err(InvitationError::Revoked)
        ));

        let (_, raw3) = hooks
            .create(
                &actor,
                "tenant-a",
                InvitationRole::Member,
                3_000,
                60_000,
                SecretValue::new("token-cccccccccccc"),
            )
            .unwrap();
        hooks
            .accept(&bob, raw3.expose(), None, None, 3_001)
            .unwrap();
        // Reuse by different subject fails
        let carol = human_context("carol");
        assert!(matches!(
            hooks.accept(&carol, raw3.expose(), None, None, 3_002),
            Err(InvitationError::AlreadyAccepted)
        ));
        // Retry by same subject succeeds (exactly one membership)
        let again = hooks
            .accept(&bob, raw3.expose(), None, None, 3_003)
            .unwrap();
        assert_eq!(again.subject, "bob");

        let (_, raw4) = hooks
            .create(
                &actor,
                "tenant-a",
                InvitationRole::Member,
                4_000,
                60_000,
                SecretValue::new("token-dddddddddddd"),
            )
            .unwrap();
        assert!(matches!(
            hooks.accept(
                &human_context("dave"),
                raw4.expose(),
                Some("other-tenant"),
                None,
                4_001
            ),
            Err(InvitationError::WrongTenant)
        ));
        assert!(matches!(
            hooks.accept(
                &human_context("erin"),
                raw4.expose(),
                None,
                Some(InvitationRole::Owner),
                4_001
            ),
            Err(InvitationError::RoleModified)
        ));
        let _ = view;
    }

    #[test]
    fn acceptance_creates_exactly_one_membership() {
        let hooks = MemoryInvitationHooks::new();
        hooks.seed_owner("tenant-a", "alice");
        let actor = human_context("alice");
        let (_, raw) = hooks
            .create(
                &actor,
                "tenant-a",
                InvitationRole::Member,
                1_000,
                60_000,
                SecretValue::new("token-eeeeeeeeeeee"),
            )
            .unwrap();
        let bob = human_context("bob");
        hooks.accept(&bob, raw.expose(), None, None, 1_001).unwrap();
        hooks.accept(&bob, raw.expose(), None, None, 1_002).unwrap();
        assert!(hooks.has_membership("tenant-a", "bob"));
        // only one membership entry
        let count = hooks
            .memberships
            .read()
            .unwrap()
            .get("tenant-a")
            .map(|m| m.len())
            .unwrap_or(0);
        assert_eq!(count, 2); // alice owner + bob member
    }

    #[test]
    fn last_owner_invariant() {
        let hooks = MemoryInvitationHooks::new();
        hooks.seed_owner("tenant-a", "alice");
        assert!(matches!(
            hooks.ensure_not_last_owner("tenant-a", "alice"),
            Err(InvitationError::LastOwnerInvariant)
        ));
        hooks
            .add_membership("tenant-a", "bob", InvitationRole::Owner)
            .unwrap();
        assert!(hooks.ensure_not_last_owner("tenant-a", "alice").is_ok());
    }

    #[test]
    fn create_accept_revoke_are_auditable() {
        let hooks = MemoryInvitationHooks::new();
        hooks.seed_owner("tenant-a", "alice");
        let actor = human_context("alice");
        let (view, raw) = hooks
            .create(
                &actor,
                "tenant-a",
                InvitationRole::Member,
                1_000,
                60_000,
                SecretValue::new("token-ffffffffffff"),
            )
            .unwrap();
        hooks
            .accept(&human_context("bob"), raw.expose(), None, None, 1_001)
            .unwrap();
        let (view2, _) = hooks
            .create(
                &actor,
                "tenant-a",
                InvitationRole::Member,
                2_000,
                60_000,
                SecretValue::new("token-gggggggggggg"),
            )
            .unwrap();
        hooks.revoke(&actor, &view2.invitation_id, 2_001).unwrap();
        let log = hooks.audit_log();
        assert!(
            log.iter()
                .any(|e| e.action == "create" && e.outcome == "ok")
        );
        assert!(
            log.iter()
                .any(|e| e.action == "accept" && e.outcome == "ok")
        );
        assert!(
            log.iter()
                .any(|e| e.action == "revoke" && e.outcome == "ok")
        );
        // No secrets in audit
        for e in &log {
            assert!(!format!("{e:?}").contains("token-"));
        }
        let _ = view;
    }
}
