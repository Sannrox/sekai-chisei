//! Namespace identifier and membership checks used by Sekai projections
//! and called from the operator console.

use crate::db::runtime_db::RuntimeDb;
use crate::sekai::security::Role;

const MAX_NAMESPACE_LEN: usize = 128;

/// Namespace identifiers allowed in URLs and health/quarantine queries
/// (fail closed on anything else).
pub fn is_safe_namespace(namespace: &str) -> bool {
    if namespace.is_empty() || namespace.len() > MAX_NAMESPACE_LEN {
        return false;
    }
    namespace
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || matches!(c, '-' | '_' | '.'))
}

/// Whether the authenticated principal may open the given namespace context.
///
/// Bootstrap principals (`root`, `local`) may select any canonical namespace so
/// local-first operators can navigate without pre-seeded memberships.
/// Other principals require an explicit namespace grant/membership.
pub fn principal_can_access_namespace(
    db: &RuntimeDb,
    principal: &str,
    namespace: &str,
) -> Result<bool, String> {
    if !is_safe_namespace(namespace) {
        return Ok(false);
    }
    if matches!(principal, "root" | "local") {
        return Ok(true);
    }
    let memberships = db.list_namespace_roles_for_principal(principal)?;
    Ok(memberships
        .iter()
        .any(|(member_namespace, _role)| member_namespace == namespace))
}

/// Namespace write access (mirrors gRPC require_namespace_write_access).
pub fn principal_can_write_namespace(
    db: &RuntimeDb,
    principal: &str,
    namespace: &str,
) -> Result<bool, String> {
    if !is_safe_namespace(namespace) {
        return Ok(false);
    }
    if matches!(principal, "root" | "local") {
        return Ok(true);
    }
    let memberships = db.list_namespace_roles_for_principal(principal)?;
    Ok(memberships
        .iter()
        .any(|(ns, role)| ns == namespace && matches!(role, Role::Editor | Role::Admin)))
}
