//! Shared SQLite/PostgreSQL conformance for open-table projections (#1479).

use std::collections::BTreeMap;
use std::sync::Arc;

use sekai_chisei::db::runtime_db::RuntimeDb;
use sekai_chisei::sekai::open_table::{
    FORMAT_ICEBERG, OPEN_TABLE_CONTRACT, OpenTableColumn, OpenTableSnapshot, OpenTableSource,
    QUERY_UNAVAILABLE, SCHEMA_REVISION_V1, SNAPSHOT_UNAVAILABLE,
};

use crate::postgres_scratch::ScratchDatabase;

fn digest(tag: u8) -> String {
    format!("sha256:{tag:02x}{}", "ab".repeat(31))
}

fn source(owner: &str, schema: u8, snapshot: u8) -> OpenTableSource {
    OpenTableSource {
        contract_version: OPEN_TABLE_CONTRACT.into(),
        source_id: "ot:orders".into(),
        namespace: "analytics".into(),
        owner: owner.into(),
        format: FORMAT_ICEBERG.into(),
        schema_revision: SCHEMA_REVISION_V1.into(),
        schema_digest: digest(schema),
        snapshot_digest: digest(snapshot),
        columns: vec![OpenTableColumn {
            name: "id".into(),
            col_type: "string".into(),
            classification: "internal".into(),
        }],
        registered_by: owner.into(),
        registered_at_ms: 1_000,
    }
}

fn snapshot(tag: u8) -> OpenTableSnapshot {
    OpenTableSnapshot {
        source_id: "ot:orders".into(),
        snapshot_digest: digest(tag),
        rows: vec![BTreeMap::from([("id".into(), "1".into())])],
    }
}

fn exercise(db: &RuntimeDb) {
    let first = source("analyst", 1, 2);
    db.put_open_table_source(&first).unwrap();
    assert_eq!(
        db.get_open_table_source("ot:orders").unwrap(),
        Some(first.clone())
    );
    db.put_open_table_source(&first).unwrap();

    let mut taken = first.clone();
    taken.owner = "other".into();
    assert_eq!(
        db.put_open_table_source(&taken).unwrap_err(),
        QUERY_UNAVAILABLE
    );

    assert_eq!(
        db.put_open_table_snapshot(&snapshot(9)).unwrap_err(),
        SNAPSHOT_UNAVAILABLE
    );
    db.put_open_table_snapshot(&snapshot(2)).unwrap();
    assert_eq!(
        db.get_open_table_snapshot("ot:orders").unwrap(),
        Some(snapshot(2))
    );

    let next = source("analyst", 1, 3);
    db.put_open_table_source(&next).unwrap();
    assert!(db.get_open_table_snapshot("ot:orders").unwrap().is_none());
    db.put_open_table_snapshot(&snapshot(3)).unwrap();
    assert_eq!(
        db.get_open_table_snapshot("ot:orders").unwrap(),
        Some(snapshot(3))
    );

    assert_eq!(
        db.put_open_table_snapshot(&OpenTableSnapshot {
            source_id: "ot:missing".into(),
            snapshot_digest: digest(3),
            rows: vec![],
        })
        .unwrap_err(),
        QUERY_UNAVAILABLE
    );
}

#[test]
fn sqlite_open_table_backend_conformance() {
    exercise(&RuntimeDb::memory());
}

#[test]
#[ignore = "requires SEKAI_TEST_POSTGRES_URL for an isolated TLS PostgreSQL database"]
fn postgres_open_table_backend_conformance() {
    let scratch = ScratchDatabase::create();
    let db = RuntimeDb::Postgres(Arc::new(scratch.connect(8)));
    exercise(&db);
}
