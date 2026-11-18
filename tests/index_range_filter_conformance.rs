//! Index range filters admit the same text values on SQLite and PostgreSQL
//! (#2995): only text matching the strict numeric pattern compares as a number.

use std::collections::{BTreeMap, HashMap};
use std::sync::Arc;

use crate::postgres_scratch::ScratchDatabase;
use sekai_chisei::db::runtime_db::RuntimeDb;
use sekai_chisei::sekai::dataset::{ColumnDef, Dataset, RowFilter, RowQuery};
use sekai_chisei::sekai::object_type_index::{CONTRACT_VERSION, ObjectTypeDatasource};

fn exercise(db: &RuntimeDb, prefix: &str) {
    let namespace = format!("{prefix}-sales");
    let dataset_id = format!("{prefix}-ds");
    let column = |name: &str| ColumnDef {
        name: name.into(),
        col_type: "string".into(),
        classification: "public".into(),
    };
    db.create_dataset(&Dataset {
        id: dataset_id.clone(),
        name: dataset_id.clone(),
        columns: vec![column("id"), column("value"), column("hidden")],
        object_id: String::new(),
        created: 1,
        partition_keys: Vec::new(),
    })
    .unwrap();
    let rows = [
        ("date", "2024-01-05"),
        ("exponent", "1e5"),
        ("plain", "50"),
        ("negative", "-3.5"),
    ]
    .map(|(id, value)| {
        HashMap::from([
            ("id".to_string(), id.to_string()),
            ("value".to_string(), value.to_string()),
            ("hidden".to_string(), "0".to_string()),
        ])
    });
    db.append_rows(&dataset_id, &rows).unwrap();
    let binding = ObjectTypeDatasource {
        contract_version: CONTRACT_VERSION.into(),
        namespace: namespace.clone(),
        kind: "Reading".into(),
        definition_digest: "rev-1".into(),
        dataset_id,
        key_column: "id".into(),
        property_mapping: BTreeMap::from([("value".into(), "value".into())]),
        hidden_column: "hidden".into(),
        edits_only: false,
        conflict_rule: String::new(),
        source_timestamp_property: String::new(),
    }
    .prepare()
    .unwrap();
    db.register_object_type_datasource(&binding, 10).unwrap();
    db.apply_object_type_index(&namespace, "Reading", true, 20)
        .unwrap();

    let matching = |op: &str, value: &str| {
        let mut keys = db
            .list_visible_index_members(
                &namespace,
                "Reading",
                &RowQuery {
                    filters: vec![RowFilter {
                        column: "value".into(),
                        op: op.into(),
                        value: value.into(),
                    }],
                    ..RowQuery::default()
                },
            )
            .unwrap()
            .into_iter()
            .map(|member| member.source_key)
            .collect::<Vec<_>>();
        keys.sort();
        keys
    };
    assert_eq!(matching("gt", "1000"), ["exponent"]);
    assert_eq!(matching("gte", "0"), ["exponent", "plain"]);
    assert_eq!(matching("lt", "100"), ["negative", "plain"]);
    assert_eq!(matching("lte", "2.5"), ["negative"]);
    assert_eq!(matching("gt", "-1000.5"), ["exponent", "negative", "plain"]);
}

#[test]
fn sqlite_index_range_filters_admit_only_strict_numeric_text() {
    exercise(&RuntimeDb::memory(), "sqlite");
}

#[test]
#[ignore = "requires SEKAI_TEST_POSTGRES_URL for an isolated TLS PostgreSQL database"]
fn postgres_index_range_filters_admit_only_strict_numeric_text() {
    let scratch = ScratchDatabase::create();
    let db = RuntimeDb::Postgres(Arc::new(scratch.connect(8)));
    exercise(&db, "postgres");
}
