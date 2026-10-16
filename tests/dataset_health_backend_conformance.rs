//! Shared SQLite/PostgreSQL conformance for dataset health checks (#1411).

use std::collections::HashMap;
use std::sync::Arc;

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
