//! Service-principal scope registry on SQLite and PostgreSQL (#1508).

use std::sync::Arc;

use sekai_chisei::db::runtime_db::RuntimeDb;
use sekai_chisei::db::{postgres::PostgresDb, sekai::SekaiDb};
use sekai_chisei::sekai::service_principal::ServicePrincipalRegistration;

fn registration(principal: &str, namespaces: &[&str], now_ms: i64) -> ServicePrincipalRegistration {
    ServicePrincipalRegistration {
        capabilities: Vec::new(),
        principal: principal.into(),
        tenant_id: "tenant-a".into(),
        namespaces: namespaces
            .iter()
            .map(|namespace| namespace.to_string())
            .collect(),
        action_types: vec!["dispatch".into()],
        registered_by: "root".into(),
        created_at_ms: now_ms,
        updated_at_ms: now_ms,
    }
}

/// Register, read, update and remove one principal.
fn exercise(db: &RuntimeDb, prefix: &str) {
    let principal = format!("{prefix}-worker");
    assert_eq!(db.get_service_principal(&principal).unwrap(), None);

    let stored = db
        .put_service_principal(&registration(&principal, &["ns-b", "ns-a"], 10))
        .unwrap()
        .unwrap();
    assert_eq!(stored.namespaces, ["ns-a", "ns-b"]);
    assert_eq!(db.get_service_principal(&principal).unwrap(), Some(stored));

    let updated = db
        .put_service_principal(&registration(&principal, &["ns-c"], 20))
        .unwrap()
        .unwrap();
    assert_eq!(updated.namespaces, ["ns-c"]);
    assert_eq!(updated.created_at_ms, 10);
    assert_eq!(updated.updated_at_ms, 20);

    assert!(
        db.put_service_principal(&registration(&principal, &[], 30))
            .is_err()
    );
    // Another tenant can neither replace nor delete the registration.
    let mut foreign = registration(&principal, &["ns-x"], 25);
    foreign.tenant_id = "tenant-b".into();
    assert_eq!(db.put_service_principal(&foreign).unwrap(), None);
    assert!(!db.delete_service_principal(&principal, "tenant-b").unwrap());
    assert_eq!(db.get_service_principal(&principal).unwrap(), Some(updated));

    assert!(db.delete_service_principal(&principal, "tenant-a").unwrap());
    assert!(!db.delete_service_principal(&principal, "tenant-a").unwrap());
    assert_eq!(db.get_service_principal(&principal).unwrap(), None);
}

#[test]
fn sqlite_service_principal_conformance() {
    let db = RuntimeDb::Sqlite(Arc::new(SekaiDb::new(":memory:").unwrap()));
    exercise(&db, "sqlite");
}

fn postgres() -> RuntimeDb {
    let url = std::env::var("SEKAI_TEST_POSTGRES_URL")
        .expect("SEKAI_TEST_POSTGRES_URL must identify an isolated PostgreSQL database");
    let db = if let Ok(path) = std::env::var("SEKAI_TEST_POSTGRES_CA_CERT") {
        PostgresDb::connect_with_ca_certificate(&url, 8, &std::fs::read(path).unwrap()).unwrap()
    } else {
        PostgresDb::connect(&url, 8).unwrap()
    };
    RuntimeDb::Postgres(Arc::new(db))
}

#[test]
#[ignore = "requires SEKAI_TEST_POSTGRES_URL for an isolated TLS PostgreSQL database"]
fn postgres_service_principal_conformance_and_restart() {
    let prefix = format!("pg-{}", uuid::Uuid::new_v4().simple());
    exercise(&postgres(), &prefix);
    // The migration is idempotent and a registration survives a reconnect.
    let principal = format!("{prefix}-durable");
    postgres()
        .put_service_principal(&registration(&principal, &["ns-a"], 1))
        .unwrap();
    assert!(
        postgres()
            .get_service_principal(&principal)
            .unwrap()
            .is_some()
    );
}
