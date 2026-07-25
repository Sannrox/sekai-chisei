//! Two-replica race harness smoke tests for #304 / #117.
//!
//! Behavioral pass criteria only: no wall-clock budgets as the sole signal.

use sekai_chisei::db::chisei_budget::METRIC_TOKENS;
use sekai_chisei::db::replica_safety::{ReplicaSafetyInventory, TwoReplicaSqlite};
use std::path::Path;

#[test]
fn inventory_fixture_is_valid_and_evidence_exists() {
    let inventory = ReplicaSafetyInventory::load().expect("load inventory");
    for surface in &inventory.surfaces {
        for path in &surface.evidence {
            assert!(
                Path::new(path).exists(),
                "missing evidence {path} for {}",
                surface.id
            );
        }
    }
    for id in &inventory.required_authoritative_surfaces {
        inventory
            .require_authoritative(id)
            .unwrap_or_else(|error| panic!("{id}: {error}"));
    }
}

#[test]
fn two_independent_stores_share_budget_authority() {
    let inventory = ReplicaSafetyInventory::load().unwrap();
    inventory.require_authoritative("chisei.budget").unwrap();

    let pair = TwoReplicaSqlite::open().expect("shared sqlite pair");
    pair.a
        .budget_set_limit("global", METRIC_TOKENS, 10, "daily")
        .unwrap();

    // Replica B observes the limit written by A.
    let (_used, max, period) = pair.b.budget_usage("global", METRIC_TOKENS, 0).unwrap();
    assert_eq!(max, 10);
    assert_eq!(period, "daily");

    let results = pair.race_results(4, |_index, db| {
        db.budget_check_and_reserve_chain("global", METRIC_TOKENS, 6, 0)
    });
    let successes = results.iter().filter(|result| result.is_ok()).count();
    assert_eq!(
        successes, 1,
        "shared limit 10 with reserve 6 admits one winner; got {results:?}"
    );
    assert_eq!(
        pair.a.budget_usage("global", METRIC_TOKENS, 0).unwrap().0,
        6
    );
    assert_eq!(
        pair.b.budget_usage("global", METRIC_TOKENS, 0).unwrap().0,
        6
    );
}

#[test]
fn process_local_surface_cannot_be_required_as_authority() {
    let inventory = ReplicaSafetyInventory::load().unwrap();
    let err = inventory
        .require_authoritative("chisei.eval.batch_scratch")
        .unwrap_err();
    assert!(err.contains("process_local_ok"), "unexpected error: {err}");
}
