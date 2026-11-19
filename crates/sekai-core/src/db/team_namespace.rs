//! Backend-neutral team-namespace bootstrap persistence.

use crate::db::{postgres::PostgresDb, sekai::SekaiDb};
use crate::domain::Object;
use crate::sekai::audit::ObjectChange;
use crate::sekai::security::{Grant, Role};

pub const POSTGRES_TEAM_NAMESPACE_SURFACE: &str = "sekai.team-namespaces";

pub trait TeamNamespaceBackend: Send + Sync {
    fn ensure_team_namespace(
        &self,
        namespace: &str,
        principal: &str,
        member_role: Role,
        actor: &str,
    ) -> Result<(Object, Vec<Grant>), String>;

    fn find_namespace_boundary(&self, namespace: &str) -> Result<Option<Object>, String>;

    fn is_team_principal(&self, principal: &str) -> Result<bool, String>;
}

macro_rules! forward {
    ($target:ty) => {
        fn ensure_team_namespace(
            &self,
            namespace: &str,
            principal: &str,
            member_role: Role,
            actor: &str,
        ) -> Result<(Object, Vec<Grant>), String> {
            <$target>::ensure_team_namespace(self, namespace, principal, member_role, actor)
        }
        fn find_namespace_boundary(&self, namespace: &str) -> Result<Option<Object>, String> {
            <$target>::find_namespace_boundary(self, namespace)
        }
        fn is_team_principal(&self, principal: &str) -> Result<bool, String> {
            <$target>::is_team_principal(self, principal)
        }
    };
}

impl TeamNamespaceBackend for SekaiDb {
    forward!(SekaiDb);
}
impl TeamNamespaceBackend for PostgresDb {
    forward!(PostgresDb);
}

/// Shared bootstrap input validation for SQLite and PostgreSQL.
pub fn validate_team_namespace_bootstrap(namespace: &str, principal: &str) -> Result<(), String> {
    let namespace = namespace.trim();
    let principal = principal.trim();
    if principal.starts_with("tenant:") || namespace.starts_with("tenant:") {
        return Err("tenant identities are not admitted by team-namespace bootstrap".into());
    }
    if namespace.is_empty()
        || namespace.len() > 128
        || namespace.contains('\0')
        || namespace.contains('/')
        || namespace.contains(':')
    {
        return Err("malformed namespace identity".into());
    }
    if principal.is_empty() || principal.len() > 128 || principal.contains('\0') {
        return Err("malformed principal".into());
    }
    Ok(())
}

/// The grant attributes a team-namespace bootstrap overwrites, in a fixed order:
/// role, purpose, expiry, and exception reason.
pub(crate) type TeamGrantAttributes = [String; 4];

const TEAM_GRANT_FIELDS: [&str; 4] = ["role", "purpose", "not_after_ms", "exception_reason"];

pub(crate) fn team_grant_attributes(grant: &Grant) -> TeamGrantAttributes {
    [
        grant.role.as_str().to_string(),
        grant.purpose.clone(),
        grant.not_after_ms.to_string(),
        grant.exception_reason.clone(),
    ]
}

/// Change rows on the namespace boundary for each attribute a bootstrap overwrote on an
/// existing grant (#2718), so a renewed expiry or purpose keeps its old value in the
/// audit trail. A grant the bootstrap creates records nothing here.
pub(crate) fn team_grant_changes(
    actor: &str,
    grant: &Grant,
    before: Option<&TeamGrantAttributes>,
    timestamp: i64,
) -> Vec<ObjectChange> {
    let Some(before) = before else {
        return Vec::new();
    };
    let after = team_grant_attributes(grant);
    TEAM_GRANT_FIELDS
        .iter()
        .zip(before.iter().zip(after))
        .filter(|(_, (old, new))| *old != new)
        .map(|(field, (old, new))| ObjectChange {
            id: uuid::Uuid::new_v4().to_string(),
            object_id: grant.object_id.clone(),
            field: format!("grants.{}.{field}", grant.principal),
            old_value: old.clone(),
            new_value: new,
            changed_by: actor.into(),
            timestamp,
            ..Default::default()
        })
        .collect()
}
