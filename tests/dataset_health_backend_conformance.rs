//! Shared SQLite/PostgreSQL conformance for dataset health checks (#1411).

use std::collections::HashMap;
use std::sync::{Arc, Barrier};

use sekai_chisei::db::dataset::DatasetBackend;
use sekai_chisei::db::runtime_db::RuntimeDb;
use sekai_chisei::sekai::dataset::{ColumnDef, Dataset, RowQuery};
use sekai_chisei::sekai::dataset_health::{
    ALERT_FIRING, ALERT_REASON_LATE, ALERT_RESOLVED, DatasetHealthCheck, KIND_FRESHNESS,
    KIND_ROW_COUNT, KIND_SCHEMA,
};

use crate::postgres_scratch::ScratchDatabase;

fn dataset(id: &str) -> Dataset {
    Dataset {
        id: id.into(),
        name: id.into(),
        columns: vec![
            ColumnDef {
                name: "kind".into(),
                col_type: "string".into(),
                classification: "public".into(),
            },
            ColumnDef {
                name: "n".into(),
                col_type: "string".into(),
                classification: "public".into(),
            },
        ],
        object_id: String::new(),
        created: 1,
        partition_keys: Vec::new(),
    }
}

fn check(id: &str, dataset_id: &str, kind: &str) -> DatasetHealthCheck {
    DatasetHealthCheck {
        dataset_id: dataset_id.into(),
        check_id: id.into(),
        kind: kind.into(),
        max_age_ms: 0,
        min_rows: 0,
        max_rows: 0,
        columns: Vec::new(),
        predicate: Vec::new(),
        blocking: false,
        every_ms: 0,
        tenant: "acme".into(),
        space: "ops".into(),
        last_run_ms: 0,
    }
}

fn exercise(db: &dyn DatasetBackend, prefix: &str) {
    let dataset_id = format!("{prefix}-health");
    db.create_dataset(&dataset(dataset_id.as_str())).unwrap();

    let mut freshness = check("fresh", &dataset_id, KIND_FRESHNESS);
    freshness.max_age_ms = 60_000;
    db.put_dataset_health_check(&freshness).unwrap();
    let mut counts = check("count", &dataset_id, KIND_ROW_COUNT);
    counts.min_rows = 1;
    counts.max_rows = 1;
    db.put_dataset_health_check(&counts).unwrap();
    let mut schema = check("schema", &dataset_id, KIND_SCHEMA);
    schema.columns = vec!["kind".into(), "n".into()];
    db.put_dataset_health_check(&schema).unwrap();

    db.append_rows(
        &dataset_id,
        &[HashMap::from([
            ("kind".into(), "v1".into()),
            ("n".into(), "1".into()),
        ])],
    )
    .unwrap();
    let versions = db.list_dataset_versions(&dataset_id).unwrap();
    let v1 = versions[0].clone();
    let passed = db
        .list_dataset_health_results(&dataset_id, &v1.version_id)
        .unwrap();
    assert_eq!(passed.len(), 3);
    assert!(passed.iter().all(|result| result.passed));

    let mut blocking = counts.clone();
    blocking.blocking = true;
    db.put_dataset_health_check(&blocking).unwrap();
    db.append_rows(
        &dataset_id,
        &[HashMap::from([
            ("kind".into(), "v2".into()),
            ("n".into(), "2".into()),
        ])],
    )
    .unwrap();
    let state = db.dataset_health_state(&dataset_id).unwrap();
    assert!(state.quarantined);
    let live = db.query_rows(&dataset_id, &RowQuery::default()).unwrap();
    assert_eq!(live.len(), 1);
    assert_eq!(live[0]["kind"], "v1");
    assert_eq!(state.last_healthy_version_id, v1.version_id);

    let mut scheduled = check("sched", &dataset_id, KIND_FRESHNESS);
    scheduled.max_age_ms = 10_000;
    scheduled.every_ms = 1_000;
    db.put_dataset_health_check(&scheduled).unwrap();
    db.run_dataset_health_checks(&dataset_id, 5_000).unwrap();
    assert!(
        db.dataset_health_state(&dataset_id).unwrap().quarantined,
        "scheduled freshness must not lift a blocking quarantine"
    );
    assert!(
        db.list_dataset_alerts(&dataset_id)
            .unwrap()
            .iter()
            .all(|alert| alert.reason != ALERT_REASON_LATE)
    );
    db.run_dataset_health_checks(&dataset_id, 7_000).unwrap();
    let firing: Vec<_> = db
        .list_dataset_alerts(&dataset_id)
        .unwrap()
        .into_iter()
        .filter(|alert| alert.reason == ALERT_REASON_LATE)
        .collect();
    assert_eq!(firing.len(), 1);
    assert_eq!(firing[0].state, ALERT_FIRING);
    assert_eq!(firing[0].tenant, "acme");
    assert_eq!(firing[0].space, "ops");
    db.run_dataset_health_checks(&dataset_id, 7_500).unwrap();
    let still: Vec<_> = db
        .list_dataset_alerts(&dataset_id)
        .unwrap()
        .into_iter()
        .filter(|alert| alert.reason == ALERT_REASON_LATE)
        .collect();
    assert_eq!(still.len(), 1);
    db.run_dataset_health_checks(&dataset_id, 8_000).unwrap();
    let late: Vec<_> = db
        .list_dataset_alerts(&dataset_id)
        .unwrap()
        .into_iter()
        .filter(|alert| alert.reason == ALERT_REASON_LATE)
        .collect();
    assert_eq!(late.len(), 2);
    assert_eq!(late[1].state, ALERT_RESOLVED);
}

/// What a binary before #2187 wrote on a cadence `RunDatasetHealthChecks`:
/// a scheduled check is due when `last_run_ms + every_ms <= now`, and the run
/// sets `last_run_ms = now`. Only that write decides whether a new plane
/// treats the bucket as taken, so the judgment itself is not replayed here.
fn old_binary_cadence_run(db: &RuntimeDb, dataset_id: &str, now_ms: i64) -> bool {
    let sql_due = "every_ms > 0 AND (last_run_ms = 0 OR last_run_ms + every_ms <= ";
    let ran = match db {
        RuntimeDb::Sqlite(sqlite) => sqlite
            .conn()
            .execute(
                &format!(
                    "UPDATE sekai_dataset_health_checks SET last_run_ms = ?1
                     WHERE dataset_id = ?2 AND {sql_due}?1)"
                ),
                rusqlite::params![now_ms, dataset_id],
            )
            .unwrap(),
        RuntimeDb::Postgres(postgres) => postgres
            .connection()
            .unwrap()
            .execute(
                &format!(
                    "UPDATE sekai_dataset_health_checks SET last_run_ms = $1
                     WHERE dataset_id = $2 AND {sql_due}$1)"
                ),
                &[&now_ms, &dataset_id],
            )
            .unwrap() as usize,
    };
    ran == 1
}

/// Two planes over one store tick at the same instant: the due check runs
/// once. A mixed deploy, where an old binary still runs checks on a cadence,
/// runs it at most once per bucket in either order (#2187).
fn exercise_schedule(plane_a: &RuntimeDb, plane_b: &RuntimeDb, prefix: &str) {
    let dataset_id = format!("{prefix}-scheduled");
    plane_a
        .create_dataset(&dataset(dataset_id.as_str()))
        .unwrap();
    plane_a
        .append_rows(
            &dataset_id,
            &[HashMap::from([
                ("kind".into(), "v1".into()),
                ("n".into(), "1".into()),
            ])],
        )
        .unwrap();
    let mut scheduled = check("sched", &dataset_id, KIND_ROW_COUNT);
    scheduled.min_rows = 1;
    scheduled.every_ms = 1_000;
    plane_a.put_dataset_health_check(&scheduled).unwrap();

    let barrier = Arc::new(Barrier::new(2));
    let ticks: Vec<_> = [plane_a.clone(), plane_b.clone()]
        .into_iter()
        .map(|plane| {
            let barrier = barrier.clone();
            std::thread::spawn(move || {
                barrier.wait();
                plane.tick_dataset_health_checks(5_500).unwrap()
            })
        })
        .collect();
    let judged: usize = ticks.into_iter().map(|tick| tick.join().unwrap()).sum();
    assert_eq!(judged, 1, "two planes ticking at once run a due check once");
    assert_eq!(plane_b.tick_dataset_health_checks(5_999).unwrap(), 0);

    // Old binary first: its run takes bucket 6 for the new planes too.
    assert!(old_binary_cadence_run(plane_a, &dataset_id, 6_500));
    assert_eq!(plane_b.tick_dataset_health_checks(6_999).unwrap(), 0);
    // New plane first: the old rule sees the claim and does not run again.
    assert_eq!(plane_a.tick_dataset_health_checks(7_500).unwrap(), 1);
    assert!(!old_binary_cadence_run(plane_b, &dataset_id, 7_999));
    // At the boundary, in both orders. New plane late in bucket 8, old binary
    // at the start of bucket 9: last + every is still ahead, so no rerun.
    assert_eq!(plane_a.tick_dataset_health_checks(8_999).unwrap(), 1);
    assert!(!old_binary_cadence_run(plane_b, &dataset_id, 9_000));
    assert_eq!(plane_b.tick_dataset_health_checks(9_000).unwrap(), 1);
    // Old binary at the start of bucket 10, new plane at its end.
    assert!(old_binary_cadence_run(plane_a, &dataset_id, 10_000));
    assert_eq!(plane_b.tick_dataset_health_checks(10_999).unwrap(), 0);
    assert_eq!(plane_a.tick_dataset_health_checks(11_000).unwrap(), 1);

    // A new binary's `RunDatasetHealthChecks` goes through the same claim,
    // so an old outside cron pointed at it dedupes with the tick.
    assert!(
        plane_a
            .run_dataset_health_checks(&dataset_id, 11_500)
            .unwrap()
            .is_empty()
    );
    assert_eq!(
        plane_a
            .run_dataset_health_checks(&dataset_id, 12_000)
            .unwrap()
            .len(),
        1
    );
    assert_eq!(plane_b.tick_dataset_health_checks(12_500).unwrap(), 0);
}

#[test]
fn sqlite_dataset_health_schedule_runs_once_across_planes() {
    let path = std::env::temp_dir().join(format!(
        "sekai-dataset-health-{}-{}.db",
        std::process::id(),
        uuid::Uuid::new_v4().simple()
    ));
    let path = path.to_string_lossy().into_owned();
    let open = || {
        RuntimeDb::Sqlite(Arc::new(
            sekai_chisei::db::sekai::SekaiDb::new(&path).unwrap(),
        ))
    };
    exercise_schedule(&open(), &open(), "sqlite");
    for suffix in ["", "-wal", "-shm"] {
        let _ = std::fs::remove_file(format!("{path}{suffix}"));
    }
}

#[test]
#[ignore = "requires SEKAI_TEST_POSTGRES_URL for an isolated TLS PostgreSQL database"]
fn postgres_dataset_health_schedule_runs_once_across_planes() {
    let scratch = ScratchDatabase::create();
    let plane_a = RuntimeDb::Postgres(Arc::new(scratch.connect(4)));
    let plane_b = RuntimeDb::Postgres(Arc::new(scratch.connect(4)));
    exercise_schedule(&plane_a, &plane_b, "pg");
}

#[test]
fn sqlite_dataset_health_backend_conformance() {
    exercise(
        &sekai_chisei::db::sekai::SekaiDb::new(":memory:").unwrap(),
        "sqlite",
    );
}

#[test]
#[ignore = "requires SEKAI_TEST_POSTGRES_URL for an isolated TLS PostgreSQL database"]
fn postgres_dataset_health_backend_conformance() {
    let scratch = ScratchDatabase::create();
    let db = RuntimeDb::Postgres(Arc::new(scratch.connect(8)));
    let prefix = format!("pg-{}", uuid::Uuid::new_v4().simple());
    match &db {
        RuntimeDb::Postgres(postgres) => exercise(postgres.as_ref(), &prefix),
        RuntimeDb::Sqlite(_) => unreachable!(),
    }
}
