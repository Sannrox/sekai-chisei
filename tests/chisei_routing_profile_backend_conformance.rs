//! Shared SQLite/PostgreSQL conformance for customer-hosted routing profiles
//! (#1171).

use sekai_chisei::chisei::routing_profiles::HostedRoutingProfile;
use sekai_chisei::db::chisei_routing_profile::ChiseiRoutingProfileBackend;
use sekai_chisei::db::{postgres::PostgresDb, sekai::SekaiDb};

fn profile(namespace: &str, name: &str, origin: &str) -> HostedRoutingProfile {
    HostedRoutingProfile {
        namespace: namespace.into(),
        profile_id: format!("hosted:{name}"),
        endpoint_origin: origin.into(),
        model_patterns: vec!["acme-*".into()],
        credential_ref: "ACME".into(),
        registered_by: "admin".into(),
        registered_at_ms: 1,
    }
}

fn exercise(db: &dyn ChiseiRoutingProfileBackend, prefix: &str) {
    let namespace = format!("{prefix}-sales");
    let foreign = format!("{prefix}-ops");
    let first = profile(&namespace, "acme", "https://a.example.com");
    db.put_hosted_routing_profile(&first).unwrap();
    db.put_hosted_routing_profile(&profile(&namespace, "beta", "https://b.example.com"))
        .unwrap();
    db.put_hosted_routing_profile(&profile(&foreign, "acme", "https://c.example.com"))
        .unwrap();

    let listed = db.list_hosted_routing_profiles(&namespace).unwrap();
    assert_eq!(
        listed
            .iter()
            .map(|profile| profile.profile_id.as_str())
            .collect::<Vec<_>>(),
        ["hosted:acme", "hosted:beta"]
    );
    assert_eq!(listed[0], first);
    assert_eq!(db.list_hosted_routing_profiles(&foreign).unwrap().len(), 1);

    // Re-registering replaces the profile in place.
    let replaced = HostedRoutingProfile {
        model_patterns: vec!["acme-2-*".into()],
        registered_at_ms: 2,
        ..first.clone()
    };
    db.put_hosted_routing_profile(&replaced).unwrap();
    assert_eq!(
        db.list_hosted_routing_profiles(&namespace).unwrap()[0],
        replaced
    );

    // Revocation is namespace-scoped and idempotent.
    assert!(
        db.revoke_hosted_routing_profile(&namespace, "hosted:acme", 3)
            .unwrap()
    );
    assert!(
        !db.revoke_hosted_routing_profile(&namespace, "hosted:acme", 4)
            .unwrap()
    );
    assert!(
        !db.revoke_hosted_routing_profile(&namespace, "hosted:missing", 4)
            .unwrap()
    );
    assert_eq!(
        db.list_hosted_routing_profiles(&namespace)
            .unwrap()
            .iter()
            .map(|profile| profile.profile_id.as_str())
            .collect::<Vec<_>>(),
        ["hosted:beta"]
    );
    assert_eq!(db.list_hosted_routing_profiles(&foreign).unwrap().len(), 1);

    // Registering again after revocation restores it.
    db.put_hosted_routing_profile(&replaced).unwrap();
    assert_eq!(
        db.list_hosted_routing_profiles(&namespace).unwrap().len(),
        2
    );
}

#[test]
fn sqlite_routing_profile_backend_conformance() {
    exercise(&SekaiDb::new(":memory:").unwrap(), "sqlite");
}

fn postgres() -> PostgresDb {
    let url = std::env::var("SEKAI_TEST_POSTGRES_URL")
        .expect("SEKAI_TEST_POSTGRES_URL must identify an isolated PostgreSQL database");
    if let Ok(path) = std::env::var("SEKAI_TEST_POSTGRES_CA_CERT") {
        PostgresDb::connect_with_ca_certificate(&url, 4, &std::fs::read(path).unwrap()).unwrap()
    } else {
        PostgresDb::connect(&url, 4).unwrap()
    }
}

#[test]
#[ignore = "requires SEKAI_TEST_POSTGRES_URL for an isolated TLS PostgreSQL database"]
fn postgres_routing_profile_backend_conformance() {
    let prefix = format!("pg-routing-{}", uuid::Uuid::new_v4().simple());
    exercise(&postgres(), &prefix);
}
