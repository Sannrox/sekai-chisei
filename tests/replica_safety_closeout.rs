//! Closeout multi-replica evidence for epic #117 / issue #309.
//!
//! Parent acceptance bullets (detailed suites listed in docs/replica-safety.md):
//! - Concurrent replicas cannot overspend a shared budget.
//! - Duplicate admission / lifecycle keys converge.
//! - Credential cache refuses revoked secrets after reload.
//! - Recoverable work is not stranded after simulated replica loss.
//! - Eval/portfolio authoritative state is shared.

use sekai_chisei::chisei::eval::{EvalStore, Suite};
use sekai_chisei::db::chisei_budget::METRIC_TOKENS;
use sekai_chisei::db::replica_safety::{ReplicaSafetyInventory, TwoReplicaSqlite};
use sekai_chisei::gateway_keys::hash_gateway_key;
use sekai_chisei::sekai::coordination::{
    ADMISSION_POLICY_FIFO, ContentionScope, ReconcileFilter, WORK_UNIT_STATUS_PENDING,
    WORK_UNIT_STATUS_STALE, WorkUnit,
};
use sekai_chisei::sekai::credentials::PrincipalCredentialStore;
use std::path::Path;
use std::sync::Arc;

#[test]
fn inventory_covers_parent_authoritative_surfaces_with_evidence() {
    let inventory = ReplicaSafetyInventory::load().expect("inventory");
    assert_eq!(inventory.parent_issue, 117);
    for id in &inventory.required_authoritative_surfaces {
        let surface = inventory
            .require_authoritative(id)
            .unwrap_or_else(|e| panic!("{e}"));
        assert!(!surface.evidence.is_empty(), "{id} missing evidence");
        for path in &surface.evidence {
            assert!(Path::new(path).exists(), "missing {path} for {id}");
        }
    }
}

#[test]
fn budget_cannot_overspend_under_two_replicas() {
    let pair = TwoReplicaSqlite::open().unwrap();
    pair.a
        .budget_set_limit("closeout", METRIC_TOKENS, 10, "daily")
        .unwrap();
    let results = pair.race_results(2, |_i, db| {
        db.budget_check_and_reserve_chain("closeout", METRIC_TOKENS, 6, 1)
    });
    assert_eq!(results.iter().filter(|r| r.is_ok()).count(), 1);
    assert_eq!(
        pair.b.budget_usage("closeout", METRIC_TOKENS, 1).unwrap().0,
        6
    );
}

#[test]
fn lease_and_admission_converge_and_stale_work_recovers() {
    let pair = TwoReplicaSqlite::open().unwrap();

    let leases = pair.race_results(2, |i, db| {
        let owner = format!("w{i}");
        db.acquire_lease("closeout-ns", "k", &owner, 1_000, &owner, &owner, 10)
    });
    assert_eq!(leases.iter().filter(|r| r.is_ok()).count(), 1);

    pair.a
        .create_contention_scope(&ContentionScope {
            id: "closeout-scope".into(),
            name: "closeout-scope".into(),
            parent_scope_id: String::new(),
            max_concurrency: 1,
            admission_policy: ADMISSION_POLICY_FIFO.into(),
            heartbeat_ttl_seconds: 2,
            timeout_seconds: 30,
            owner_principal: "owner".into(),
            created: 1,
            updated: 1,
        })
        .unwrap();
    let unit = WorkUnit {
        id: "wu-closeout".into(),
        kind: "build".into(),
        actor: "actor".into(),
        target_object_id: String::new(),
        status: WORK_UNIT_STATUS_PENDING.into(),
        requested_spec: "{}".into(),
        scope_id: "closeout-scope".into(),
        priority: 0,
        timeout_seconds: 30,
        heartbeat_ttl_seconds: 2,
        created_at: 10,
        admitted_at: 0,
        started_at: 0,
        finished_at: 0,
        last_heartbeat_at: 0,
        failure_reason: String::new(),
        cancel_reason: String::new(),
        owner_principal: "owner".into(),
        creator_principal: "creator".into(),
        idempotency_key: "closeout-key".into(),
        updated_at: 10,
    };
    pair.a.create_work_unit(&unit).unwrap();
    assert!(
        pair.b
            .try_admit_work_unit("wu-closeout", "worker-a", 100)
            .unwrap()
            .admitted
    );

    let summary = pair
        .a
        .reconcile_work_units(
            100 + 5_000,
            &ReconcileFilter {
                work_unit_id: Some("wu-closeout".into()),
                limit: 5,
                ..Default::default()
            },
        )
        .unwrap();
    assert!(summary.work_units_reconciled >= 1);
    assert_eq!(
        pair.b.get_work_unit("wu-closeout").unwrap().unwrap().status,
        WORK_UNIT_STATUS_STALE
    );
}

#[test]
fn credential_reload_and_eval_share_across_replicas() {
    let pair = TwoReplicaSqlite::open().unwrap();
    let secret = "closeout-secret";
    let hash = hash_gateway_key(secret);
    pair.a
        .create_principal_credential("alice", &hash, 1_000)
        .unwrap();
    let store = PrincipalCredentialStore::new();
    assert!(store.maybe_reload(&pair.b));
    assert!(store.resolve(secret).is_some());
    pair.a.revoke_principal_credential("alice").unwrap();
    assert!(store.maybe_reload(&pair.b));
    assert!(store.resolve(secret).is_none());

    let writer = EvalStore::with_db(Arc::clone(&pair.a));
    let reader = EvalStore::with_db(Arc::clone(&pair.b));
    writer
        .put_suite(Suite {
            id: "closeout-suite".into(),
            name: "closeout".into(),
            description: String::new(),
            cases: Vec::new(),
        })
        .unwrap();
    assert_eq!(reader.get_suite("closeout-suite").unwrap().name, "closeout");
}
