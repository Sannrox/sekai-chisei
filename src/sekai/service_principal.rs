//! Service-principal scope registrations (#1508, ADR 0099).
//!
//! A registration records the narrow scope of a worker that acts as a service
//! principal: the Action types it may run and the tenant and namespaces it may
//! address. The marking ceiling is the principal's existing profile
//! `classification_ceiling`, so it is not stored here. Credentials and token
//! issuance belong to the identity extension; a registration never holds a
//! secret. Enforcement of these scopes is separate work.

use std::collections::BTreeSet;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ServicePrincipalRegistration {
    pub principal: String,
    /// Owning tenant; empty only for a registration made without tenant
    /// authority (no identity extension, tenant-less caller).
    pub tenant_id: String,
    /// Namespaces the principal may address, sorted and unique.
    pub namespaces: Vec<String>,
    /// Action type ids the principal may run, sorted and unique.
    pub action_types: Vec<String>,
    pub registered_by: String,
    pub created_at_ms: i64,
    pub updated_at_ms: i64,
}

impl ServicePrincipalRegistration {
    /// Validate and canonicalize a registration before it is stored.
    pub fn normalized(mut self) -> Result<Self, String> {
        if !valid_principal(&self.principal) {
            return Err("service principal must match [a-zA-Z0-9._-]+ and not be built-in".into());
        }
        if self.tenant_id != self.tenant_id.trim() {
            return Err("tenant_id must not have surrounding whitespace".into());
        }
        self.namespaces = canonical_list("namespaces", self.namespaces)?;
        self.action_types = canonical_list("action_types", self.action_types)?;
        Ok(self)
    }
}

/// Built-in principals with trusted authority are never service principals.
const RESERVED_PRINCIPALS: &[&str] = &["root", "local", "anonymous", "chisei-gateway"];

fn valid_principal(principal: &str) -> bool {
    !principal.is_empty()
        && !RESERVED_PRINCIPALS.contains(&principal)
        && principal
            .chars()
            .all(|ch| ch.is_ascii_alphanumeric() || matches!(ch, '.' | '_' | '-'))
}

/// Sorted, unique, non-empty list of trimmed, non-empty entries.
fn canonical_list(field: &str, values: Vec<String>) -> Result<Vec<String>, String> {
    let mut canonical = BTreeSet::new();
    for value in values {
        let trimmed = value.trim();
        if trimmed.is_empty() || trimmed.contains(',') {
            return Err(format!("{field} entries must be non-empty and comma-free"));
        }
        canonical.insert(trimmed.to_string());
    }
    if canonical.is_empty() {
        return Err(format!("{field} must not be empty"));
    }
    Ok(canonical.into_iter().collect())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn registration() -> ServicePrincipalRegistration {
        ServicePrincipalRegistration {
            principal: "worker-a".into(),
            tenant_id: "tenant-a".into(),
            namespaces: vec!["ns-b".into(), " ns-a ".into(), "ns-b".into()],
            action_types: vec!["dispatch".into()],
            registered_by: "root".into(),
            created_at_ms: 1,
            updated_at_ms: 1,
        }
    }

    #[test]
    fn normalizes_lists_and_rejects_empty_scopes() {
        let normalized = registration().normalized().unwrap();
        assert_eq!(normalized.namespaces, ["ns-a", "ns-b"]);
        let mut empty = registration();
        empty.action_types.clear();
        assert!(empty.normalized().is_err());
        let mut blank = registration();
        blank.namespaces = vec![" ".into()];
        assert!(blank.normalized().is_err());
        let mut bad = registration();
        bad.principal = "worker,root".into();
        assert!(bad.normalized().is_err());
        let mut builtin = registration();
        builtin.principal = "root".into();
        assert!(builtin.normalized().is_err());
    }
}
