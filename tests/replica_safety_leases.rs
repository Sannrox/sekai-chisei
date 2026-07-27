//! Replica-safe leases, admission, and recovery after replica loss (#306 / #117).

use sekai_chisei::db::replica_safety::{ReplicaSafetyInventory, TwoReplicaSqlite};
use sekai_chisei::sekai::coordination::{
    ADMISSION_POLICY_FIFO, ContentionScope, ReconcileFilter, WORK_UNIT_STATUS_PENDING,
    WORK_UNIT_STATUS_STALE, WorkUnit,
};
use sekai_chisei::sekai::lease::LeaseError;

fn scope(id: &str) -> ContentionScope {
    ContentionScope {
        id: id.into(),
        name: id.into(),
        parent_scope_id: String::new(),
        max_concurrency: 1,
        admission_policy: ADMISSION_POLICY_FIFO.into(),
        heartbeat_ttl_seconds: 2,
        timeout_seconds: 30,
        owner_principal: "owner".into(),
        created: 1,
        updated: 1,
    }
}

fn work(id: &str, scope_id: &str, created: i64, idempotency_key: &str) -> WorkUnit {
    WorkUnit {
        id: id.into(),
        kind: "build".into(),
        actor: "actor".into(),
        target_object_id: String::new(),
        status: WORK_UNIT_STATUS_PENDING.into(),
        requested_spec: "{}".into(),
        scope_id: scope_id.into(),
        priority: 0,
        timeout_seconds: 30,
        heartbeat_ttl_seconds: 2,
        created_at: created,
        admitted_at: 0,
        started_at: 0,
        finished_at: 0,
        last_heartbeat_at: 0,
        failure_reason: String::new(),
        cancel_reason: String::new(),
        owner_principal: "owner".into(),
        creator_principal: "creator".into(),
        idempotency_key: idempotency_key.into(),
        updated_at: created,
    }
}

#[test]
fn inventory_marks_leases_and_coordination_authoritative() {
    let inventory = ReplicaSafetyInventory::load().unwrap();
    inventory.require_authoritative("sekai.leases").unwrap();
    inventory
        .require_authoritative("sekai.coordination")
        .unwrap();
}

#[test]
fn concurrent_lease_acquire_has_one_winner_across_replicas() {
    let pair = TwoReplicaSqlite::open().unwrap();
    let namespace = "ns-lease";
    let key = "shared-key";

    let results = pair.race_results(4, |index, db| {
        let owner = format!("worker-{index}");
        db.acquire_lease(namespace, key, &owner, 1_000, &owner, &owner, "local", 10)
    });
    let successes: Vec<_> = results.iter().filter(|r| r.is_ok()).collect();
    let failures: Vec<_> = results.iter().filter(|r| r.is_err()).collect();
    assert_eq!(successes.len(), 1, "results={results:?}");
    assert_eq!(failures.len(), 3, "results={results:?}");
    for err in failures {
        match err.as_ref().unwrap_err() {
            LeaseError::Conflict(_) => {}
            other => panic!("expected Conflict, got {other:?}"),
        }
    }
    let winner = successes[0].as_ref().unwrap();
    // Both replicas observe the same holder.
    assert!(
        pair.b
            .acquire_lease(
                namespace,
                key,
                "latecomer",
                1_000,
                "late-req",
                "latecomer",
                "local",
                20
            )
            .is_err()
    );
    assert_eq!(winner.namespace, namespace);
    assert_eq!(winner.key, key);
}

#[test]
fn same_request_id_reacquire_converges_across_replicas() {
    let pair = TwoReplicaSqlite::open().unwrap();
    let first = pair
        .a
        .acquire_lease("ns", "k", "owner-a", 500, "req-1", "actor", "local", 10)
        .unwrap();
    // Replica B retries the same request id for the same owner.
    let replay = pair
        .b
        .acquire_lease("ns", "k", "owner-a", 500, "req-1", "actor", "local", 11)
        .unwrap();
    assert_eq!(first, replay);
    assert_eq!(first.fencing_token, replay.fencing_token);
}

#[test]
fn expired_lease_can_be_taken_over_by_another_replica() {
    let pair = TwoReplicaSqlite::open().unwrap();
    let acquired = pair
        .a
        .acquire_lease("ns", "k", "owner-a", 100, "acq", "actor-a", "local", 10)
        .unwrap();
    assert_eq!(acquired.expires_at_ms, 110);

    // Before expiry, takeover refuses.
    let not_expired = pair.b.takeover_expired_lease(
        "ns",
        "k",
        "owner-b",
        &acquired.fencing_token,
        acquired.expires_at_ms,
        100,
        "take-early",
        "actor-b",
        "local",
        50,
    );
    assert!(matches!(not_expired, Err(LeaseError::NotExpired)));

    // After expiry, the other replica reclaims.
    let takeover = pair
        .b
        .takeover_expired_lease(
            "ns",
            "k",
            "owner-b",
            &acquired.fencing_token,
            acquired.expires_at_ms,
            100,
            "take-late",
            "actor-b",
            "local",
            acquired.expires_at_ms,
        )
        .unwrap();
    assert_eq!(takeover.owner, "owner-b");
    assert_eq!(takeover.generation, acquired.generation + 1);
    assert_ne!(takeover.fencing_token, acquired.fencing_token);

    // Original owner cannot refresh with the stale token.
    assert!(
        pair.a
            .refresh_lease(
                "ns",
                "k",
                &acquired.fencing_token,
                100,
                "stale-refresh",
                "actor-a",
                "local",
                acquired.expires_at_ms + 1
            )
            .is_err()
    );
}

#[test]
fn admission_race_admits_one_work_unit_under_shared_scope() {
    let pair = TwoReplicaSqlite::open().unwrap();
    pair.a.create_contention_scope(&scope("scope-1")).unwrap();
    let first = work("wu-a", "scope-1", 10, "key-a");
    let second = work("wu-b", "scope-1", 10, "key-b");
    pair.a.create_work_unit(&first).unwrap();
    // Create second via B so both replicas are used for durable writes.
    pair.b.create_work_unit(&second).unwrap();

    let results = pair.race_results(2, |index, db| {
        let id = if index == 0 { "wu-a" } else { "wu-b" };
        db.try_admit_work_unit(id, id, 100)
    });
    let admitted = results
        .iter()
        .map(|r| r.as_ref().unwrap())
        .filter(|r| r.admitted)
        .count();
    assert_eq!(admitted, 1, "results={results:?}");
}

#[test]
fn duplicate_work_unit_idempotency_key_converges() {
    let pair = TwoReplicaSqlite::open().unwrap();
    pair.a.create_contention_scope(&scope("scope-dup")).unwrap();
    let unit = work("wu-1", "scope-dup", 10, "same-key");
    pair.a.create_work_unit(&unit).unwrap();

    // Second create with same idempotency key should not invent a second authority.
    let duplicate = work("wu-2", "scope-dup", 11, "same-key");
    let err = pair.b.create_work_unit(&duplicate);
    // Either error or resolve to the first — both are safe if get-by-key is unique.
    match err {
        Ok(()) => {
            // If insert is ignored/accepted, lookup must still return a single logical unit.
            let found = pair
                .a
                .get_work_unit_by_idempotency_key("same-key")
                .unwrap()
                .expect("key present");
            assert_eq!(found.idempotency_key, "same-key");
        }
        Err(message) => {
            assert!(
                !message.is_empty(),
                "duplicate create should surface a clear error"
            );
            let found = pair
                .b
                .get_work_unit_by_idempotency_key("same-key")
                .unwrap()
                .unwrap();
            assert_eq!(found.id, "wu-1");
        }
    }
}

#[test]
fn stale_admitted_work_is_recoverable_via_reconcile_on_other_replica() {
    let pair = TwoReplicaSqlite::open().unwrap();
    pair.a
        .create_contention_scope(&scope("scope-stale"))
        .unwrap();
    let unit = work("wu-stale", "scope-stale", 10, "stale-key");
    pair.a.create_work_unit(&unit).unwrap();
    let admitted = pair
        .a
        .try_admit_work_unit("wu-stale", "worker-a", 100)
        .unwrap();
    assert!(admitted.admitted);

    // Far future: heartbeat TTL (2s) from admitted_at/last_heartbeat is long expired.
    let summary = pair
        .b
        .reconcile_work_units(
            100 + 2_000 * 2,
            &ReconcileFilter {
                work_unit_id: Some("wu-stale".into()),
                limit: 10,
                ..Default::default()
            },
        )
        .unwrap();
    assert!(summary.work_units_reconciled >= 1, "summary={summary:?}");
    let after = pair.b.get_work_unit("wu-stale").unwrap().unwrap();
    assert_eq!(after.status, WORK_UNIT_STATUS_STALE);

    // Scope capacity free for a new unit after recover.
    let next = work("wu-next", "scope-stale", 20, "next-key");
    pair.a.create_work_unit(&next).unwrap();
    assert!(
        pair.a
            .try_admit_work_unit("wu-next", "worker-b", 100 + 2_000 * 2 + 1)
            .unwrap()
            .admitted
    );
}
