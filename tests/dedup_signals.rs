//! Deduplication and idempotency signals, isolated in their own test binary.
//!
//! The Prometheus recorder is process-global; a sibling test emitting these
//! series directly would satisfy the assertions with the instrumentation
//! deleted. Each `tests/*.rs` runs in its own process.

use sekai_chisei::chisei::budget::BudgetTracker;
use sekai_chisei::db::runtime_db::RuntimeDb;
use sekai_chisei::db::sekai::SekaiDb;
use sekai_chisei::obs::signals;
use std::sync::Arc;

fn dedup_count(rendered: &str, event: &str) -> u64 {
    rendered
        .lines()
        .find(|line| {
            line.starts_with(signals::DEDUPLICATION_TOTAL)
                && line.contains(&format!(r#"event="{event}""#))
        })
        .and_then(|line| line.rsplit(' ').next()?.parse().ok())
        .unwrap_or(0)
}

#[test]
fn replays_and_conflicts_are_counted_separately() {
    sekai_chisei::obs::metrics::handle();

    let db = Arc::new(RuntimeDb::Sqlite(Arc::new(
        SekaiDb::new(":memory:").expect("open in-memory database"),
    )));
    let budget = BudgetTracker::new(db);

    let before = sekai_chisei::obs::metrics::handle().render();
    assert_eq!(dedup_count(&before, "idempotent_replay"), 0);
    assert_eq!(dedup_count(&before, "idempotency_conflict"), 0);

    // First write with this key is genuinely new: no dedup event.
    let first = budget
        .record_idempotent_with_metric("scope-a", 10, "tokens", "key-1")
        .expect("first record succeeds");
    assert!(first, "first write should report as newly recorded");

    let after_first = sekai_chisei::obs::metrics::handle().render();
    assert_eq!(
        dedup_count(&after_first, "idempotent_replay"),
        0,
        "a first write must not count as a replay:\n{after_first}"
    );

    // Same key, same payload: a suppressed retry.
    let replay = budget
        .record_idempotent_with_metric("scope-a", 10, "tokens", "key-1")
        .expect("replay is not an error");
    assert!(!replay, "replay should report as already recorded");

    let after_replay = sekai_chisei::obs::metrics::handle().render();
    assert_eq!(
        dedup_count(&after_replay, "idempotent_replay"),
        1,
        "suppressed retry was not recorded:\n{after_replay}"
    );

    // Same key, different payload: a conflict, not a replay.
    let conflict = budget.record_idempotent_with_metric("scope-a", 999, "tokens", "key-1");
    assert!(conflict.is_err(), "key reuse with a new payload must fail");

    let after_conflict = sekai_chisei::obs::metrics::handle().render();
    assert_eq!(
        dedup_count(&after_conflict, "idempotency_conflict"),
        1,
        "idempotency conflict was not recorded:\n{after_conflict}"
    );
    assert_eq!(
        dedup_count(&after_conflict, "idempotent_replay"),
        1,
        "a conflict must not also count as a replay:\n{after_conflict}"
    );
}
