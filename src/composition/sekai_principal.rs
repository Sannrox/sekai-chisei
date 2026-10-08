//! Composition wiring for Chisei principal grants over the Sekai store
//! (ADR 0096 rule 6).
//!
//! Mapping lives in [`crate::chisei::sekai_principal`]. These inherent
//! methods sit here because they name `RuntimeDb`, which Chisei must not.

use crate::chisei::principal::{MarkingClearance, PrincipalGrant};
use crate::chisei::sekai_principal::principal_grants;
use crate::db::runtime_db::RuntimeDb;
use crate::db::sekai::SekaiDb;
use crate::db::store::SekaiStore;
use crate::domain::Object;
use crate::sekai::classification_lattice::evaluate_lattice_access;
use crate::sekai::markings;
use crate::sekai::security::{Grant, Role};

impl SekaiDb {
    /// Grants on `object_id` as Chisei sees them.
    pub fn list_principal_grants(&self, object_id: &str) -> Result<Vec<PrincipalGrant>, String> {
        self.list_grants(object_id)
            .map(|grants| principal_grants(&grants))
    }
}

impl RuntimeDb {
    /// Grants on `object_id` as Chisei sees them.
    pub fn list_principal_grants(&self, object_id: &str) -> Result<Vec<PrincipalGrant>, String> {
        self.list_grants(object_id)
            .map(|grants| principal_grants(&grants))
    }

    /// Record a Sekai grant described in Chisei terms. Fixture seeding uses
    /// it so Chisei code never builds a Sekai `Grant` itself.
    pub fn create_principal_grant(
        &self,
        grant_id: &str,
        object_id: &str,
        grant: &PrincipalGrant,
        created: i64,
    ) -> Result<(), String> {
        self.create_grant(&Grant {
            id: grant_id.into(),
            object_id: object_id.into(),
            principal: grant.principal.clone(),
            role: grant.role.into(),
            created,
        })
    }
}

impl SekaiStore {
    /// Classification-marking clearance of `principal` for `object`.
    ///
    /// Unmarked objects never consult the principal profile. Marked objects
    /// are evaluated with the namespace classification lattice (or the
    /// default evidence lattice when none is configured); anything but an
    /// explicit lattice deny clears. Storage errors and an ambiguous trusted
    /// principal profile are errors, which callers treat as a deny.
    pub fn principal_marking_clearance(
        &self,
        operation_id: &str,
        object: &Object,
        principal: &str,
    ) -> Result<MarkingClearance, String> {
        let Some(marking) = markings::object_marking_token(object) else {
            return Ok(MarkingClearance::Unmarked);
        };
        let authority = trusted_principal_authority(self.runtime(), principal)?;
        let lattice = self
            .runtime()
            .get_classification_lattice(&object.namespace)?;
        let decision =
            evaluate_lattice_access(operation_id, Some(marking), &authority, lattice.as_ref())
                .decision;
        Ok(if decision == markings::MarkingDecision::Deny {
            MarkingClearance::Denied
        } else {
            MarkingClearance::Cleared
        })
    }
}

/// Principal authority from the single sealed, admin-granted principal
/// profile, or the trusted-service authority for local service subjects.
fn trusted_principal_authority(
    db: &RuntimeDb,
    principal: &str,
) -> Result<markings::PrincipalAuthority, String> {
    if let Some(trusted) = markings::trusted_service_authority(principal) {
        return Ok(trusted);
    }
    let candidates =
        db.find_all_by_external_id(&markings::principal_profile_external_id(principal))?;
    let mut trusted_profiles = Vec::new();
    for object in &candidates {
        if object.kind != markings::PRINCIPAL_PROFILE_KIND
            || object
                .properties
                .get(markings::PRINCIPAL_PROFILE_SEALED_PROPERTY)
                .is_none_or(|value| value != "true")
        {
            continue;
        }
        let grants = db.list_grants(&object.id)?;
        if grants.iter().any(|grant| matches!(grant.role, Role::Admin)) {
            trusted_profiles.push(object);
        }
    }
    if trusted_profiles.len() > 1 {
        return Err("multiple trusted principal profiles found".into());
    }
    markings::principal_authority_from_profile(principal, trusted_profiles.first().copied())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::chisei::principal::{PrincipalGrant, PrincipalRole};
    use std::collections::HashMap;

    fn object(id: &str, properties: &[(&str, &str)]) -> Object {
        Object {
            id: id.into(),
            kind: "widget".into(),
            name: id.into(),
            namespace: "acme".into(),
            external_id: format!("widget:{id}"),
            properties: properties
                .iter()
                .map(|(key, value)| (key.to_string(), value.to_string()))
                .collect::<HashMap<_, _>>(),
            created: 1,
            updated: 1,
        }
    }

    #[test]
    fn listed_principal_grants_match_the_sekai_grants_written() {
        let sekai = SekaiStore::memory();
        sekai
            .runtime()
            .create_object(&object("object", &[]))
            .unwrap();
        sekai
            .runtime()
            .create_principal_grant(
                "grant-alice",
                "object",
                &PrincipalGrant::new("alice", PrincipalRole::Editor),
                1,
            )
            .unwrap();
        let written = sekai.runtime().list_grants("object").unwrap();
        assert_eq!(written.len(), 1);
        assert_eq!(written[0].role, Role::Editor);
        assert_eq!(
            sekai.runtime().list_principal_grants("object").unwrap(),
            [PrincipalGrant::new("alice", PrincipalRole::Editor)]
        );
    }

    #[test]
    fn marking_clearance_follows_the_sekai_lattice() {
        let sekai = SekaiStore::memory();
        let unmarked = object("unmarked", &[]);
        let restricted = object(
            "restricted",
            &[(markings::OBJECT_CLASSIFICATION_PROPERTY, "restricted")],
        );
        for (principal, target, expected) in [
            ("alice", &unmarked, MarkingClearance::Unmarked),
            ("alice", &restricted, MarkingClearance::Denied),
            ("chisei-gateway", &restricted, MarkingClearance::Cleared),
            ("root", &restricted, MarkingClearance::Cleared),
        ] {
            let clearance = sekai
                .principal_marking_clearance("test", target, principal)
                .unwrap();
            let authority = trusted_principal_authority(sekai.runtime(), principal).unwrap();
            let sekai_denies = evaluate_lattice_access(
                "test",
                markings::object_marking_token(target),
                &authority,
                None,
            )
            .decision
                == markings::MarkingDecision::Deny;
            assert_eq!(clearance, expected, "{principal} {}", target.id);
            assert_eq!(
                clearance.allows(),
                !sekai_denies,
                "{principal} {}",
                target.id
            );
        }
    }

    #[test]
    fn marked_objects_follow_sekai_clearance_through_the_principal_context() {
        use crate::composition::lookup_first::{LookupDecision, try_lookup_first};
        use crate::sekai::semantic;
        let db = SekaiStore::memory();
        crate::composition::lookup_first::seed_s1_fixture_graph(&db).expect("seed");
        let marked = Object {
            id: "lookup-marked".into(),
            kind: "widget".into(),
            name: "lookup-marked".into(),
            namespace: "acme".into(),
            external_id: "widget:lookup-marked".into(),
            properties: std::collections::HashMap::from([(
                markings::OBJECT_CLASSIFICATION_PROPERTY.to_string(),
                "restricted".to_string(),
            )]),
            created: 1,
            updated: 1,
        };
        db.runtime().create_object(&marked).unwrap();
        let retrieve = |actor: &str| {
            try_lookup_first(
                semantic::CAPABILITY_RETRIEVE_CONTEXT,
                "acme",
                actor,
                r#"{"roots":[{"object_id":"lookup-marked"}],"direction":"outgoing","max_depth":1}"#,
                &db,
            )
            .unwrap()
        };
        let denied = |decision: &LookupDecision| matches!(decision, LookupDecision::Refusal { reason, .. } if reason == "acl_denied");

        // No clearance: the marking denies even though no grant restricts it.
        assert!(denied(&retrieve("alice")));
        // Trusted service subjects clear every marking.
        assert!(matches!(
            retrieve("chisei-gateway"),
            LookupDecision::Hit { .. }
        ));

        // A sealed, admin-granted principal profile raises alice's clearance.
        let profile = Object {
            id: "profile-alice".into(),
            kind: markings::PRINCIPAL_PROFILE_KIND.into(),
            name: "alice".into(),
            namespace: "acme".into(),
            external_id: markings::principal_profile_external_id("alice"),
            properties: std::collections::HashMap::from([
                (
                    markings::PRINCIPAL_CLASSIFICATION_CEILING_PROPERTY.to_string(),
                    "restricted".to_string(),
                ),
                (
                    markings::PRINCIPAL_PROFILE_SEALED_PROPERTY.to_string(),
                    "true".to_string(),
                ),
            ]),
            created: 1,
            updated: 1,
        };
        db.runtime().create_object(&profile).unwrap();
        assert!(
            denied(&retrieve("alice")),
            "an unsealed-by-admin profile must not raise clearance"
        );
        db.runtime()
            .create_principal_grant(
                "grant-profile-alice",
                "profile-alice",
                &PrincipalGrant::new("credential-admin", PrincipalRole::Admin),
                1,
            )
            .unwrap();
        assert!(matches!(retrieve("alice"), LookupDecision::Hit { .. }));
    }
}
