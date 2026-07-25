//! Shared budget authority under concurrent replicas (#305 / #117).
//!
//! Uses the two-replica SQLite harness. Pass criteria are durable outcomes only.

use sekai_chisei::db::chisei_budget::METRIC_TOKENS;
use sekai_chisei::db::replica_safety::{ReplicaSafetyInventory, TwoReplicaSqlite};
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};

#[test]
fn concurrent_replicas_cannot_overspend_shared_limit() {
    let inventory = ReplicaSafetyInventory::load().unwrap();
    inventory.require_authoritative("chisei.budget").unwrap();

    let pair = TwoReplicaSqlite::open().unwrap();
    pair.a
        .budget_set_limit("ns", METRIC_TOKENS, 100, "daily")
        .unwrap();

    // Eight workers each try to reserve 40 against limit 100 → at most two winners (80),
    // never three (120). With 40 and limit 100, floor(100/40)=2.
    let results = pair.race_results(8, |_index, db| {
        db.budget_check_and_reserve_chain("ns", METRIC_TOKENS, 40, 1_000)
    });
    let successes = results.iter().filter(|r| r.is_ok()).count();
    assert!(
        successes <= 2,
        "at most two 40-token reserves under limit 100; successes={successes} results={results:?}"
    );
    assert!(successes >= 1, "at least one reserve should succeed");
    let used = pair.b.budget_usage("ns", METRIC_TOKENS, 1_000).unwrap().0;
    assert_eq!(used, successes as i64 * 40);
    assert!(used <= 100, "used {used} exceeds limit");
}

#[test]
fn idempotent_reserve_converges_across_replicas() {
    let pair = TwoReplicaSqlite::open().unwrap();
    pair.a
        .budget_set_limit("global", METRIC_TOKENS, 50, "daily")
        .unwrap();

    let key = "idem-reserve-shared-key";
    let results = pair.race_results(4, |_index, db| {
        db.budget_check_and_reserve_chain_idempotent("global", METRIC_TOKENS, 25, 2_000, key)
    });
    let oks = results.iter().filter(|r| r.is_ok()).count();
    assert_eq!(oks, 4, "same key+payload must all report Ok; {results:?}");
    // Only one physical reservation of 25.
    assert_eq!(
        pair.a
            .budget_usage("global", METRIC_TOKENS, 2_000)
            .unwrap()
            .0,
        25
    );
    assert_eq!(
        pair.b
            .budget_usage("global", METRIC_TOKENS, 2_000)
            .unwrap()
            .0,
        25
    );
}

#[test]
fn idempotent_record_does_not_double_spend_across_replicas() {
    let pair = TwoReplicaSqlite::open().unwrap();
    pair.a
        .budget_set_limit("agent", METRIC_TOKENS, 1_000, "daily")
        .unwrap();

    let key = "idem-record-shared-key";
    let first_writes = Arc::new(AtomicUsize::new(0));
    let results = pair.race_results(6, {
        let first_writes = Arc::clone(&first_writes);
        move |_index, db| {
            let wrote = db.budget_record_idempotent("agent", METRIC_TOKENS, 10, key, 3_000)?;
            if wrote {
                first_writes.fetch_add(1, Ordering::SeqCst);
            }
            Ok::<bool, String>(wrote)
        }
    });
    assert!(results.iter().all(|r| r.is_ok()), "{results:?}");
    assert_eq!(
        first_writes.load(Ordering::SeqCst),
        1,
        "exactly one first write for the idempotency key"
    );
    assert_eq!(
        pair.b
            .budget_usage("agent", METRIC_TOKENS, 3_000)
            .unwrap()
            .0,
        10
    );
}

#[test]
fn conflicting_idempotency_payload_is_rejected_not_double_spent() {
    let pair = TwoReplicaSqlite::open().unwrap();
    pair.a
        .budget_set_limit("global", METRIC_TOKENS, 100, "daily")
        .unwrap();
    pair.a
        .budget_record_idempotent("global", METRIC_TOKENS, 7, "conflict-key", 4_000)
        .unwrap();

    // Same key, different amount from the other replica.
    let err = pair
        .b
        .budget_record_idempotent("global", METRIC_TOKENS, 9, "conflict-key", 4_001)
        .unwrap_err();
    assert!(
        err.contains("idempotency") || err.contains("different"),
        "unexpected error: {err}"
    );
    assert_eq!(
        pair.a
            .budget_usage("global", METRIC_TOKENS, 4_001)
            .unwrap()
            .0,
        7
    );
}

#[test]
fn limit_written_on_one_replica_is_enforced_on_the_other() {
    let pair = TwoReplicaSqlite::open().unwrap();
    pair.a
        .budget_set_limit("shared", METRIC_TOKENS, 5, "daily")
        .unwrap();
    // B tries to reserve 6 against A's limit of 5.
    let err = pair
        .b
        .budget_check_and_reserve_chain("shared", METRIC_TOKENS, 6, 5_000)
        .unwrap_err();
    assert!(!err.is_empty());
    assert_eq!(
        pair.a
            .budget_usage("shared", METRIC_TOKENS, 5_000)
            .unwrap()
            .0,
        0
    );
}
