//! Backend-neutral team-namespace bootstrap persistence.

use crate::db::{postgres::PostgresDb, sekai::SekaiDb};
use crate::domain::Object;
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
pub(crate) fn validate_team_namespace_bootstrap(
    namespace: &str,
    principal: &str,
) -> Result<(), String> {
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
