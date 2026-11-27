//! The object type index join on both backends (#3509): an incremental apply
//! replaces only the join rows of the keys it touched, and ends where a full
//! rebuild would.

use std::collections::{BTreeMap, HashMap};

use crate::db::runtime_db::RuntimeDb;
use crate::sekai::dataset::{ColumnDef, Dataset};
use crate::sekai::object_type_index::{CONTRACT_VERSION, ObjectTypeDatasource};

fn customer(id: &str, region: &str, hidden: &str) -> HashMap<String, String> {
    HashMap::from([
        ("customer_id".into(), id.into()),
        ("region".into(), region.into()),
        ("hidden".into(), hidden.into()),
    ])
}

fn join(db: &RuntimeDb) -> Vec<(String, String)> {
    let regions = ["apac", "eu", "us"].map(String::from);
    let mut pairs = db
        .list_index_join_children("sales", "Customer", "region", &regions)
        .unwrap();
    pairs.sort();
    pairs
}

fn incremental_apply_updates_only_touched_join_rows(db: &RuntimeDb) {
    db.create_dataset(&Dataset {
        id: "ds-customers".into(),
        name: "ds-customers".into(),
        columns: ["customer_id", "region", "hidden"]
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
    db.append_rows(
        "ds-customers",
        &[customer("c1", "eu", "0"), customer("c2", "us", "0")],
    )
    .unwrap();
    let binding = ObjectTypeDatasource {
        contract_version: CONTRACT_VERSION.into(),
        namespace: "sales".into(),
        kind: "Customer".into(),
        definition_digest: "rev-1".into(),
        dataset_id: "ds-customers".into(),
        key_column: "customer_id".into(),
        property_mapping: BTreeMap::from([("region".into(), "region".into())]),
        hidden_column: "hidden".into(),
        edits_only: false,
        conflict_rule: String::new(),
        source_timestamp_property: String::new(),
    }
    .prepare()
    .unwrap();
    db.register_object_type_datasource(&binding, 10).unwrap();
    db.apply_object_type_index("sales", "Customer", true, 20)
        .unwrap();
    // c1 moves region, c2 becomes hidden, c3 is new.
    db.append_rows(
        "ds-customers",
        &[
            customer("c1", "apac", "0"),
            customer("c2", "us", "true"),
            customer("c3", "eu", "0"),
        ],
    )
    .unwrap();
    db.apply_object_type_index("sales", "Customer", false, 30)
        .unwrap();
    let incremental = join(db);
    assert_eq!(
        incremental,
        [("apac", "c1"), ("eu", "c3")].map(|(region, key)| (region.into(), key.into()))
    );
    assert!(db.hop_projection_ready("sales", "Customer").unwrap());
    db.apply_object_type_index("sales", "Customer", true, 40)
        .unwrap();
    assert_eq!(join(db), incremental);
}

#[test]
fn sqlite_incremental_apply_updates_only_touched_join_rows() {
    incremental_apply_updates_only_touched_join_rows(&RuntimeDb::memory());
}

#[test]
#[ignore = "requires SEKAI_TEST_POSTGRES_URL for a TLS PostgreSQL server the test may create databases on"]
fn postgres_incremental_apply_updates_only_touched_join_rows() {
    let scratch = crate::db::postgres::ScratchDatabase::create();
    incremental_apply_updates_only_touched_join_rows(&RuntimeDb::Postgres(std::sync::Arc::new(
        scratch.connect(),
    )));
}
