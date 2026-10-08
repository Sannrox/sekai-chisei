//! Chisei-side mapping from Sekai roles and grants (ADR 0096 rule 6).
//!
//! Chisei evaluates authorization only against
//! [`crate::chisei::principal`]. This module maps Sekai roles and grants into
//! Chisei grants. Store methods that read those grants live in composition
//! so this plane never names the Sekai runtime store.

use crate::chisei::principal::{PrincipalGrant, PrincipalRole};
use crate::sekai::security::{Grant, Role};

impl From<&Role> for PrincipalRole {
    fn from(role: &Role) -> Self {
        match role {
            Role::Viewer => Self::Viewer,
            Role::Editor => Self::Editor,
            Role::Admin => Self::Admin,
        }
    }
}

impl From<PrincipalRole> for Role {
    fn from(role: PrincipalRole) -> Self {
        match role {
            PrincipalRole::Viewer => Self::Viewer,
            PrincipalRole::Editor => Self::Editor,
            PrincipalRole::Admin => Self::Admin,
        }
    }
}

impl From<&Grant> for PrincipalGrant {
    fn from(grant: &Grant) -> Self {
        Self {
            principal: grant.principal.clone(),
            role: PrincipalRole::from(&grant.role),
        }
    }
}

/// Map Sekai grants into the grants Chisei evaluates.
pub fn principal_grants(grants: &[Grant]) -> Vec<PrincipalGrant> {
    grants.iter().map(PrincipalGrant::from).collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::chisei::principal::PrincipalContext;

    fn sekai_grant(principal: &str, role: Role) -> Grant {
        Grant {
            id: format!("grant-{principal}"),
            object_id: "object".into(),
            principal: principal.into(),
            role,
            created: 1,
        }
    }

    #[test]
    fn roles_round_trip_between_sekai_and_chisei() {
        for role in [Role::Viewer, Role::Editor, Role::Admin] {
            assert_eq!(Role::from(PrincipalRole::from(&role)), role);
        }
    }

    /// The decisions Chisei made against Sekai grants before the principal
    /// context, written out directly against `Role` and `Grant`.
    fn sekai_may_read(actor: &str, grants: &[Grant]) -> bool {
        matches!(actor, "root" | "local")
            || grants.is_empty()
            || grants.iter().any(|grant| grant.principal == actor)
    }

    fn sekai_role(actor: &str, grants: &[Grant]) -> Option<Role> {
        grants
            .iter()
            .find(|grant| grant.principal == actor)
            .map(|grant| grant.role.clone())
    }

    fn sekai_is_admin(actor: &str, grants: &[Grant]) -> bool {
        grants
            .iter()
            .any(|grant| grant.principal == actor && matches!(grant.role, Role::Admin))
    }

    #[test]
    fn adapted_grants_decide_exactly_like_sekai_grants() {
        let grant_sets = [
            vec![],
            vec![sekai_grant("bob", Role::Viewer)],
            vec![sekai_grant("alice", Role::Viewer)],
            vec![
                sekai_grant("bob", Role::Admin),
                sekai_grant("alice", Role::Editor),
                sekai_grant("alice", Role::Admin),
            ],
            vec![sekai_grant("root", Role::Viewer)],
        ];
        for actor in [
            "alice",
            "bob",
            "root",
            "local",
            "",
            " alice",
            "chisei-gateway",
        ] {
            let context = PrincipalContext::from_credential(actor);
            for grants in &grant_sets {
                let adapted = principal_grants(grants);
                assert_eq!(
                    context.may_read(&adapted),
                    sekai_may_read(actor, grants),
                    "{actor} {grants:?}"
                );
                assert_eq!(
                    context.role_in(&adapted),
                    sekai_role(actor, grants).as_ref().map(PrincipalRole::from),
                    "{actor} {grants:?}"
                );
                assert_eq!(
                    context.is_admin_in(&adapted),
                    sekai_is_admin(actor, grants),
                    "{actor} {grants:?}"
                );
            }
        }
    }
}
