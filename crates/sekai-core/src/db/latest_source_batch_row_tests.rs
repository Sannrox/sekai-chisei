//! `latest_source_batch_row` on both backends (#3259): newest row per key,
//! quarantine served from the last healthy version, and index use.

use std::collections::HashMap;

use crate::db::runtime_db::RuntimeDb;
use crate::sekai::dataset::{ColumnDef, Dataset};
use crate::sekai::dataset_health::{DatasetHealthCheck, KIND_ROW_COUNT};

const DATASET: &str = "srcds:binding-1:Issue";

fn create(db: &RuntimeDb, min_rows: i32, max_rows: i32) {
    db.create_dataset(&Dataset {
        id: DATASET.into(),
        name: DATASET.into(),
        columns: ["source_id", "v"]
            .into_iter()
            .map(|name| ColumnDef {
                name: name.into(),
                col_type: "string".into(),
                classification: "public".into(),
            })
            .collect(),
        object_id: String::new(),
        created: 1,
        partition_keys: Vec::new(),
    })
    .unwrap();
    db.put_dataset_health_check(&DatasetHealthCheck {
        dataset_id: DATASET.into(),
        check_id: "rows".into(),
        kind: KIND_ROW_COUNT.into(),
        max_age_ms: 0,
        min_rows,
        max_rows,
        columns: Vec::new(),
        predicate: Vec::new(),
        blocking: true,
        every_ms: 0,
        tenant: "acme".into(),
        space: "ops".into(),
        last_run_ms: 0,
    })
    .unwrap();
}

fn row(key: &str, v: &str) -> HashMap<String, String> {
    HashMap::from([("source_id".into(), key.into()), ("v".into(), v.into())])
}

fn latest(db: &RuntimeDb, key: &str) -> Option<String> {
    db.latest_source_batch_row(DATASET, key)
        .unwrap()
        .map(|mut row| row.remove("v").unwrap())
}

fn newest_row_wins_and_quarantine_serves_the_healthy_version(db: &RuntimeDb) {
    create(db, 1, 3);
    db.append_rows(DATASET, &[row("a", "1"), row("b", "1")])
        .unwrap();
    db.append_rows(DATASET, &[row("a", "2")]).unwrap();
    assert_eq!(latest(db, "a").as_deref(), Some("2"));
    assert_eq!(latest(db, "b").as_deref(), Some("1"));
    assert_eq!(latest(db, "missing"), None);
    // A fourth row fails the blocking check: readers stay on the version
    // that held a/1, b/1, a/2, and its newest `a` is still 2.
    db.append_rows(DATASET, &[row("a", "3")]).unwrap();
    assert!(db.dataset_health_state(DATASET).unwrap().quarantined);
    assert_eq!(latest(db, "a").as_deref(), Some("2"));
    assert_eq!(latest(db, "b").as_deref(), Some("1"));
}

fn quarantine_without_a_healthy_version_serves_nothing(db: &RuntimeDb) {
    create(db, 2, 0);
    db.append_rows(DATASET, &[row("a", "1")]).unwrap();
    let state = db.dataset_health_state(DATASET).unwrap();
    assert!(state.quarantined && state.last_healthy_version_id.is_empty());
    assert_eq!(latest(db, "a"), None);
}

#[test]
fn newest_row_wins_and_quarantine_serves_the_healthy_version_sqlite() {
    newest_row_wins_and_quarantine_serves_the_healthy_version(&RuntimeDb::memory());
}

#[test]
fn quarantine_without_a_healthy_version_serves_nothing_sqlite() {
    quarantine_without_a_healthy_version_serves_nothing(&RuntimeDb::memory());
}

#[test]
fn sqlite_lookups_seek_the_source_key_indexes() {
    let db = crate::db::sekai::SekaiDb::new(":memory:").unwrap();
    let conn = db.conn();
    for (sql, index) in [
        (
            crate::sekai::dataset::LATEST_SOURCE_ROW_SQL,
            "idx_dataset_rows_source_key",
        ),
        (
            crate::sekai::dataset::LATEST_SOURCE_VERSION_ROW_SQL,
            "idx_dataset_version_rows_source_key",
        ),
    ] {
        let mut stmt = conn.prepare(&format!("EXPLAIN QUERY PLAN {sql}")).unwrap();
        let plan: Vec<String> = stmt
            .query_map(
                rusqlite::params_from_iter(
                    ["srcds:b:Issue", "v", "a"]
                        .iter()
                        .take(stmt.parameter_count()),
                ),
                |row| row.get::<_, String>(3),
            )
            .unwrap()
            .collect::<Result<_, _>>()
            .unwrap();
        assert!(
            plan.iter().any(|step| step.contains(index))
                && !plan.iter().any(|s| s.contains("TEMP B-TREE")),
            "{sql} plan {plan:?} does not seek {index} in order"
        );
    }
}

#[test]
#[ignore = "requires SEKAI_TEST_POSTGRES_URL for a TLS PostgreSQL server the test may create databases on"]
fn postgres_latest_source_batch_row_matches_sqlite() {
    for scenario in [
        newest_row_wins_and_quarantine_serves_the_healthy_version as fn(&RuntimeDb),
        quarantine_without_a_healthy_version_serves_nothing,
    ] {
        let scratch = crate::db::postgres::ScratchDatabase::create();
        scenario(&RuntimeDb::Postgres(std::sync::Arc::new(scratch.connect())));
    }
}

#[test]
#[ignore = "requires SEKAI_TEST_POSTGRES_URL for a TLS PostgreSQL server the test may create databases on"]
fn postgres_lookups_can_seek_the_source_key_indexes() {
    let scratch = crate::db::postgres::ScratchDatabase::create();
    let db = scratch.connect();
    let mut conn = db.connection().unwrap();
    let mut tx = conn.transaction().unwrap();
    // Empty tables favor a sequential scan; forbidding it shows the planner
    // can prove the partial index predicate from the query.
    tx.batch_execute("SET LOCAL enable_seqscan = off").unwrap();
    for (sql, index) in [
        (
            crate::db::postgres_dataset::LATEST_SOURCE_ROW_SQL,
            "idx_dataset_rows_source_key",
        ),
        (
            crate::db::postgres_dataset::LATEST_SOURCE_VERSION_ROW_SQL,
            "idx_dataset_version_rows_source_key",
        ),
    ] {
        let explain = format!(
            "EXPLAIN {}",
            sql.replace("$1", "'srcds:b:Issue'")
                .replace("$2", "'v'")
                .replace("$3", "'a'")
        );
        let plan: Vec<String> = tx
            .query(&explain, &[])
            .unwrap()
            .into_iter()
            .map(|row| row.get(0))
            .collect();
        assert!(
            plan.iter().any(|step| step.contains(index)),
            "{sql} plan {plan:?} does not use {index}"
        );
    }
}
