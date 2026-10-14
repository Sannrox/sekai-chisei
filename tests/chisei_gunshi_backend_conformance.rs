//! Shared SQLite/PostgreSQL conformance for Gunshi allocation state (#1474).

use sekai_chisei::db::runtime_db::RuntimeDb;
use sekai_chisei::db::store::{ChiseiGunshiStore, ChiseiStore};

fn exercise(store: &ChiseiStore, prefix: &str) {
    let namespace = format!("{prefix}-sales");
    let foreign = format!("{prefix}-ops");
    let missing = format!("{prefix}-missing");
    let first = r#"{"namespace":"ns","revision":"r1"}"#;
    let second = r#"{"namespace":"ns","revision":"r2"}"#;

    assert!(
        store
            .get_gunshi_allocation_state(&namespace)
            .unwrap()
            .is_none()
    );

    assert!(
        store
            .put_gunshi_allocation_state_cas(&namespace, "r1", 10, first, None)
            .unwrap()
    );
    assert_eq!(
        store
            .get_gunshi_allocation_state(&namespace)
            .unwrap()
            .as_deref(),
        Some(first)
    );

    // A second install on the same namespace must not replace the row.
    assert!(
        !store
            .put_gunshi_allocation_state_cas(&namespace, "r2", 11, "{}", None)
            .unwrap()
    );
    assert_eq!(
        store
            .get_gunshi_allocation_state(&namespace)
            .unwrap()
            .as_deref(),
        Some(first)
    );

    // CAS against a missing row, or the wrong revision, leaves state unchanged.
    assert!(
        !store
            .put_gunshi_allocation_state_cas(&missing, "r1", 1, "{}", Some("r1"))
            .unwrap()
    );
    assert!(
        !store
            .put_gunshi_allocation_state_cas(&namespace, "r2", 12, "{}", Some("stale"))
            .unwrap()
    );
    assert_eq!(
        store
            .get_gunshi_allocation_state(&namespace)
            .unwrap()
            .as_deref(),
        Some(first)
    );

    assert!(
        store
            .put_gunshi_allocation_state_cas(&namespace, "r2", 13, second, Some("r1"))
            .unwrap()
    );
    assert_eq!(
        store
            .get_gunshi_allocation_state(&namespace)
            .unwrap()
            .as_deref(),
        Some(second)
    );

    assert!(
        !store
            .put_gunshi_allocation_state_cas(&namespace, "r3", 14, "{}", Some("r1"))
            .unwrap()
    );
    assert_eq!(
        store
            .get_gunshi_allocation_state(&namespace)
            .unwrap()
            .as_deref(),
        Some(second)
    );

    assert!(
        store
            .get_gunshi_allocation_state(&foreign)
            .unwrap()
            .is_none()
    );
    assert!(
        store
            .put_gunshi_allocation_state_cas(&foreign, "r1", 20, first, None)
            .unwrap()
    );
    assert_eq!(
        store
            .get_gunshi_allocation_state(&namespace)
            .unwrap()
            .as_deref(),
        Some(second)
    );
    assert_eq!(
        store
            .get_gunshi_allocation_state(&foreign)
            .unwrap()
            .as_deref(),
        Some(first)
    );
}

#[test]
fn sqlite_gunshi_allocation_backend_conformance() {
    exercise(&ChiseiStore::memory(), "sqlite");
}

#[test]
#[ignore = "requires SEKAI_TEST_POSTGRES_URL for an isolated TLS PostgreSQL database"]
fn postgres_gunshi_allocation_backend_conformance() {
    use sekai_chisei::db::postgres::PostgresDb;
    let url = std::env::var("SEKAI_TEST_POSTGRES_URL")
        .expect("SEKAI_TEST_POSTGRES_URL must identify an isolated PostgreSQL database");
    let postgres = if let Ok(path) = std::env::var("SEKAI_TEST_POSTGRES_CA_CERT") {
        PostgresDb::connect_with_ca_certificate(&url, 4, &std::fs::read(path).unwrap()).unwrap()
    } else {
        PostgresDb::connect(&url, 4).unwrap()
    };
    let prefix = format!("pg-gunshi-{}", uuid::Uuid::new_v4().simple());
    let store = ChiseiStore::from_shared_runtime(std::sync::Arc::new(RuntimeDb::Postgres(
        std::sync::Arc::new(postgres),
    )));
    exercise(&store, &prefix);
}
