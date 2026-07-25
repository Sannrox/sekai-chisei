//! Shared SQLite/PostgreSQL conformance for Chisei budget limits, reservation,
//! and idempotent usage events.

use sekai_chisei::db::chisei_budget::ChiseiBudgetBackend;
use sekai_chisei::db::{postgres::PostgresDb, sekai::SekaiDb};

trait BudgetHarness: ChiseiBudgetBackend {}
impl BudgetHarness for SekaiDb {}
impl BudgetHarness for PostgresDb {}

fn exercise(db: &dyn BudgetHarness, prefix: &str) {
    let scope = format!("{prefix}:project:agent");
    db.budget_set_limit(&scope, "tokens", 100, "daily").unwrap();
    db.budget_check_and_reserve_chain(&scope, "tokens", 40, 1_700_000_000_000)
        .unwrap();
    let (used, max, period) = db
        .budget_usage(&scope, "tokens", 1_700_000_000_000)
        .unwrap();
    assert_eq!((used, max, period.as_str()), (40, 100, "daily"));

    db.budget_check_and_reserve_chain_idempotent(
        &scope,
        "tokens",
        10,
        1_700_000_000_000,
        &format!("{prefix}-idem-1"),
    )
    .unwrap();
    // Replay with same key/payload is a no-op.
    db.budget_check_and_reserve_chain_idempotent(
        &scope,
        "tokens",
        10,
        1_700_000_000_000,
        &format!("{prefix}-idem-1"),
    )
    .unwrap();
    let (used, _, _) = db
        .budget_usage(&scope, "tokens", 1_700_000_000_000)
        .unwrap();
    assert_eq!(used, 50);

    // Conflicting payload for the same key fails closed.
    assert!(
        db.budget_check_and_reserve_chain_idempotent(
            &scope,
            "tokens",
            11,
            1_700_000_000_000,
            &format!("{prefix}-idem-1"),
        )
        .unwrap_err()
        .contains("idempotency key")
    );

    assert!(
        db.budget_check_and_reserve_chain(&scope, "tokens", 60, 1_700_000_000_000)
            .unwrap_err()
            .contains("budget exceeded")
    );

    assert!(
        db.budget_record_idempotent(
            &scope,
            "tokens",
            5,
            &format!("{prefix}-record-1"),
            1_700_000_000_000,
        )
        .unwrap()
    );
    assert!(
        !db.budget_record_idempotent(
            &scope,
            "tokens",
            5,
            &format!("{prefix}-record-1"),
            1_700_000_000_000,
        )
        .unwrap()
    );
    let (used, _, _) = db
        .budget_usage(&scope, "tokens", 1_700_000_000_000)
        .unwrap();
    assert_eq!(used, 55);
}

#[test]
fn sqlite_chisei_budget_conformance() {
    let db = SekaiDb::new(":memory:").unwrap();
    exercise(&db, "sqlite");
}

fn postgres() -> PostgresDb {
    let url = std::env::var("SEKAI_TEST_POSTGRES_URL")
        .expect("SEKAI_TEST_POSTGRES_URL must identify an isolated PostgreSQL database");
    if let Ok(path) = std::env::var("SEKAI_TEST_POSTGRES_CA_CERT") {
        PostgresDb::connect_with_ca_certificate(&url, 8, &std::fs::read(path).unwrap()).unwrap()
    } else {
        PostgresDb::connect(&url, 8).unwrap()
    }
}

#[test]
#[ignore = "requires SEKAI_TEST_POSTGRES_URL for an isolated TLS PostgreSQL database"]
fn postgres_chisei_budget_conformance_and_restart() {
    let prefix = format!("pg-{}", uuid::Uuid::new_v4().simple());
    exercise(&postgres(), &prefix);
    let restarted = postgres();
    let scope = format!("{prefix}:project:agent");
    let (used, max, _) = restarted
        .budget_usage(&scope, "tokens", 1_700_000_000_000)
        .unwrap();
    assert_eq!((used, max), (55, 100));
}
