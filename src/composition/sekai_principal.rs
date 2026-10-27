//! Composition re-export of Chisei principal grants over the Sekai store.

pub use chisei_core::sekai_principal::*;

#[cfg(test)]
mod tests {
    use super::*;
    use crate::chisei::principal::{PrincipalGrant, PrincipalRole};
    use crate::db::store::SekaiStore;
    use crate::domain::Object;
    use crate::sekai::markings;

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
