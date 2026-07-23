use sekai_chisei::db::coordination::CoordinationBackend;
use sekai_chisei::db::{postgres::PostgresDb, sekai::SekaiDb};
use sekai_chisei::sekai::coordination::*;
use std::collections::HashMap;
use std::sync::{Arc, Barrier};

fn scope(prefix: &str) -> ContentionScope {
    ContentionScope {
        id: format!("{prefix}-scope"),
        name: format!("{prefix}-scope"),
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

fn work(prefix: &str, suffix: &str, created: i64) -> WorkUnit {
    WorkUnit {
        id: format!("{prefix}-{suffix}"),
        kind: "build".into(),
        actor: "actor".into(),
        target_object_id: String::new(),
        status: WORK_UNIT_STATUS_PENDING.into(),
        requested_spec: "{}".into(),
        scope_id: format!("{prefix}-scope"),
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
        idempotency_key: format!("{prefix}-{suffix}-key"),
        updated_at: created,
    }
}

fn exercise(db: &dyn CoordinationBackend, prefix: &str) {
    db.create_contention_scope(&scope(prefix)).unwrap();
    let first = work(prefix, "first", 10);
    let second = work(prefix, "second", 20);
    db.create_work_unit(&first).unwrap();
    db.create_work_unit(&second).unwrap();
    assert_eq!(
        db.get_work_unit_by_idempotency_key(&first.idempotency_key)
            .unwrap()
            .unwrap()
            .id,
        first.id
    );
    assert_eq!(
        db.list_work_units(&WorkUnitFilter::default()).unwrap()[0].id,
        first.id
    );

    let admitted = db.try_admit_work_unit(&first.id, "worker-a", 100).unwrap();
    assert!(admitted.admitted);
    assert_eq!(admitted.reservations.len(), 1);
    let blocked = db.try_admit_work_unit(&second.id, "worker-b", 101).unwrap();
    assert!(!blocked.admitted);
    assert!(blocked.reason.contains("saturated"));

    db.heartbeat_work_unit(&first.id, 200).unwrap();
    assert_eq!(
        db.list_reservations(&ReservationFilter {
            work_unit_id: Some(first.id.clone()),
            ..Default::default()
        })
        .unwrap()[0]
            .expires_at,
        2200
    );
    db.append_run_event(&RunEvent {
        id: format!("{prefix}-custom"),
        work_unit_id: first.id.clone(),
        event_type: "custom".into(),
        message: "evidence".into(),
        evidence: HashMap::from([("digest".into(), "abc".into())]),
        created_at: 201,
    })
    .unwrap();
    assert!(
        db.list_run_events(&first.id, 100, 0, &[], None)
            .unwrap()
            .iter()
            .any(|event| event.evidence.get("digest").is_some_and(|v| v == "abc"))
    );
    let request = RequestDedup {
        request_id: format!("{prefix}-request"),
        operation: "admit".into(),
        principal: "owner".into(),
        scope_id: first.scope_id.clone(),
        work_unit_id: first.id.clone(),
        created_at: 202,
    };
    db.record_dedup_request(&request).unwrap();
    db.record_dedup_request(&request).unwrap();
    assert_eq!(
        db.get_dedup_request(&request.request_id, &request.operation)
            .unwrap(),
        Some(request)
    );
    db.complete_work_unit(&first.id, 300).unwrap();
    assert_eq!(
        db.get_work_unit(&first.id).unwrap().unwrap().status,
        WORK_UNIT_STATUS_COMPLETED
    );
    assert!(
        db.try_admit_work_unit(&second.id, "worker-b", 301)
            .unwrap()
            .admitted
    );
    let summary = db
        .reconcile_work_units(
            2402,
            &ReconcileFilter {
                limit: 1,
                ..Default::default()
            },
        )
        .unwrap();
    assert_eq!(summary.work_units_reconciled, 1);
    assert_eq!(db.coordination_snapshot(2402).unwrap().stale_count, 1);
}

#[test]
fn sqlite_coordination_conformance() {
    exercise(&SekaiDb::new(":memory:").unwrap(), "sqlite");
}

fn postgres() -> PostgresDb {
    let url = std::env::var("SEKAI_TEST_POSTGRES_URL")
        .expect("SEKAI_TEST_POSTGRES_URL must identify an isolated PostgreSQL database");
    PostgresDb::connect(&url, 8).unwrap()
}

#[test]
#[ignore = "requires SEKAI_TEST_POSTGRES_URL for an isolated TLS PostgreSQL database"]
fn postgres_coordination_conformance() {
    exercise(
        &postgres(),
        &format!("pg-{}", uuid::Uuid::new_v4().simple()),
    );
}

#[test]
#[ignore = "requires SEKAI_TEST_POSTGRES_URL for an isolated TLS PostgreSQL database"]
fn postgres_admission_race_has_one_winner() {
    let db = Arc::new(postgres());
    let prefix = format!("race-{}", uuid::Uuid::new_v4().simple());
    db.create_contention_scope(&scope(&prefix)).unwrap();
    let first = work(&prefix, "first", 10);
    let second = work(&prefix, "second", 10);
    db.create_work_unit(&first).unwrap();
    db.create_work_unit(&second).unwrap();
    let barrier = Arc::new(Barrier::new(3));
    let handles = [first.id, second.id].map(|id| {
        let db = db.clone();
        let barrier = barrier.clone();
        std::thread::spawn(move || {
            barrier.wait();
            db.try_admit_work_unit(&id, &id, 100)
        })
    });
    barrier.wait();
    let results = handles.map(|handle| handle.join().unwrap().unwrap());
    assert_eq!(results.iter().filter(|result| result.admitted).count(), 1);
}
