//! Shared SQLite/PostgreSQL conformance for Chisei budget limits, reservation,
//! and idempotent usage events.

use sekai_chisei::db::chisei_budget::ChiseiBudgetBackend;
use sekai_chisei::db::retention::RetentionPolicyBackend;
use sekai_chisei::db::{postgres::PostgresDb, sekai::SekaiDb};
use sekai_chisei::sekai::retention::SubjectErasureRequest;

trait BudgetHarness: ChiseiBudgetBackend + RetentionPolicyBackend {}
impl BudgetHarness for SekaiDb {}
impl BudgetHarness for PostgresDb {}

fn exercise(db: &dyn BudgetHarness, prefix: &str) {
    let scope = format!("{prefix}:project:agent");
    db.budget_set_limit(&scope, "tokens", 100, "daily").unwrap();
    let limits = db.budget_limits_for_scope(&scope).unwrap();
    assert!(
        limits
            .iter()
            .any(|(stored_scope, metric, max_amount, period)| {
                stored_scope == &scope
                    && metric == "tokens"
                    && *max_amount == 100
                    && period == "daily"
            }),
        "GetEffectivePolicySummary budget-limit projection must match the stored limit: {limits:?}"
    );
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

    // GetBudgetUsage reads the whole chain, tokens and requests per level.
    // `global` is shared with other runs on the same database, so only the
    // run's own scope is asserted by value.
    let levels = db.budget_usage_chain(&scope, 1_700_000_000_000).unwrap();
    let level = |scope_id: &str, metric: &str| {
        levels
            .iter()
            .find(|level| level.scope_id == scope_id && level.metric == metric)
            .map(|level| {
                (
                    level.used,
                    level.limit,
                    level.remaining(),
                    level.period_type.as_str(),
                )
            })
            .unwrap_or_else(|| panic!("{scope_id} {metric} missing: {levels:?}"))
    };
    assert_eq!(levels.len(), 4, "{levels:?}");
    assert_eq!(level(&scope, "tokens"), (55, Some(100), Some(45), "daily"));
    assert_eq!(level(&scope, "requests"), (0, None, None, "daily"));
}

/// A scope's work-unit default (#1862) caps each of its work units without a
/// limit of their own, separately; an explicit limit overrides it, and an
/// unset or cleared default leaves work units unlimited.
fn exercise_work_unit_defaults(db: &dyn BudgetHarness, prefix: &str) {
    const NOW: i64 = 1_700_000_000_000;
    let agent = format!("{prefix}:project:p/agent:a");
    let turn = |name: &str| format!("{agent}/work_unit:{name}");

    // Unset: a work unit without its own limit is unlimited.
    db.budget_check_and_reserve_chain(&turn("t0"), "tokens", 1_000, NOW)
        .unwrap();

    db.budget_set_work_unit_default(&agent, "tokens", 10, "weekly", "")
        .unwrap();
    db.budget_set_limit(&turn("t3"), "tokens", 20, "daily")
        .unwrap();

    // Refused: t1 spent 6 of its default 10. t2 counts on its own.
    db.budget_check_and_reserve_chain(&turn("t1"), "tokens", 6, NOW)
        .unwrap();
    let refused = db
        .budget_check_and_reserve_chain(&turn("t1"), "tokens", 5, NOW)
        .unwrap_err();
    assert!(refused.contains(&turn("t1")), "{refused}");
    db.budget_check_and_reserve_chain(&turn("t2"), "tokens", 10, NOW)
        .unwrap();
    // Allowed: t3's own limit overrides the default.
    db.budget_check_and_reserve_chain(&turn("t3"), "tokens", 15, NOW)
        .unwrap();
    // The default covers only direct work units of the scope that sets it.
    db.budget_check_and_reserve_chain(
        &format!("{prefix}:project:p/agent:b/work_unit:t1"),
        "tokens",
        1_000,
        NOW,
    )
    .unwrap();
    // Recorded usage lands in the default's period.
    db.budget_record_idempotent(&turn("t1"), "tokens", 1, &format!("{prefix}-t1"), NOW)
        .unwrap();

    let level = |scope: &str, metric: &str| {
        let levels = db.budget_usage_chain(scope, NOW).unwrap();
        let level = levels
            .into_iter()
            .find(|level| level.scope_id == scope && level.metric == metric)
            .unwrap();
        (
            level.used,
            level.limit,
            level.period_type,
            level.from_work_unit_default,
        )
    };
    assert_eq!(
        level(&turn("t1"), "tokens"),
        (7, Some(10), "weekly".into(), true)
    );
    assert_eq!(
        level(&turn("t1"), "requests"),
        (0, None, "daily".into(), false)
    );
    assert_eq!(
        level(&turn("t3"), "tokens"),
        (15, Some(20), "daily".into(), false)
    );
    assert_eq!(
        db.budget_usage(&turn("t1"), "tokens", NOW).unwrap(),
        (7, 10, "weekly".into())
    );
    assert!(db.budget_limits_for_scope(&turn("t1")).unwrap().contains(&(
        turn("t1"),
        "tokens".into(),
        10,
        "weekly".into()
    )));

    // Cleared: t1 is unlimited again.
    db.budget_clear_work_unit_default(&agent, "tokens").unwrap();
    db.budget_clear_work_unit_default(&agent, "tokens").unwrap();
    db.budget_check_and_reserve_chain(&turn("t1"), "tokens", 1_000, NOW)
        .unwrap();

    // Erasing a principal removes the defaults its scopes carry.
    let erased = format!("{prefix}-erased");
    let erased_turn = format!("{prefix}:project:p/agent:{erased}/work_unit:t1");
    db.budget_set_work_unit_default(
        &format!("{prefix}:project:p/agent:{erased}"),
        "tokens",
        0,
        "daily",
        "",
    )
    .unwrap();
    assert!(
        db.budget_check_and_reserve_chain(&erased_turn, "tokens", 1, NOW)
            .is_err()
    );
    db.erase_subject(&SubjectErasureRequest {
        subject_kind: "agent".into(),
        subject: erased,
        requested_by: "privacy-operator".into(),
        reason: "validated request".into(),
        timestamp: NOW,
    })
    .unwrap();
    db.budget_check_and_reserve_chain(&erased_turn, "tokens", 1, NOW)
        .unwrap();
}

#[test]
fn sqlite_chisei_budget_conformance() {
    let db = SekaiDb::new(":memory:").unwrap();
    exercise(&db, "sqlite");
    exercise_work_unit_defaults(&db, "sqlite");
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
    exercise_work_unit_defaults(&postgres(), &prefix);
    let restarted = postgres();
    let scope = format!("{prefix}:project:agent");
    let (used, max, _) = restarted
        .budget_usage(&scope, "tokens", 1_700_000_000_000)
        .unwrap();
    assert_eq!((used, max), (55, 100));
    let limits = restarted.budget_limits_for_scope(&scope).unwrap();
    assert!(
        limits
            .iter()
            .any(|(stored_scope, metric, max_amount, period)| {
                stored_scope == &scope
                    && metric == "tokens"
                    && *max_amount == 100
                    && period == "daily"
            }),
        "restarted GetEffectivePolicySummary budget-limit projection must match the stored limit: {limits:?}"
    );
}
