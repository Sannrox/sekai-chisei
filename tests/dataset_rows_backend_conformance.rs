//! `AppendRows` and `QueryRows` storage behaves the same on SQLite and
//! PostgreSQL through the community `RuntimeDb` (#1320): appended rows read
//! back in order, filters (an omitted operator is equality), projection,
//! offset and limit agree, and an empty append writes no version.

use std::collections::HashMap;
use std::sync::Arc;

use sekai_chisei::db::runtime_db::RuntimeDb;
use sekai_chisei::sekai::dataset::{ColumnDef, Dataset, RowFilter, RowQuery};

use crate::postgres_scratch::ScratchDatabase;

fn row(kind: &str, n: &str) -> HashMap<String, String> {
    HashMap::from([("kind".into(), kind.into()), ("n".into(), n.into())])
}

fn exercise(db: &RuntimeDb, id: &str) {
    let column = |name: &str| ColumnDef {
        name: name.into(),
        col_type: "string".into(),
        classification: "public".into(),
    };
    db.create_dataset(&Dataset {
        id: id.into(),
        name: id.into(),
        columns: vec![column("kind"), column("n")],
        object_id: String::new(),
        created: 1,
        partition_keys: Vec::new(),
    })
    .unwrap();
    assert_eq!(
        db.append_rows(id, &[row("a", "1"), row("b", "2"), row("a", "3")])
            .unwrap(),
        3
    );
    assert_eq!(db.append_rows(id, &[row("a", "4")]).unwrap(), 1);
    let versions = db.list_dataset_versions(id).unwrap().len();
    // An empty append is no change and no new version.
    assert_eq!(db.append_rows(id, &[]).unwrap(), 0);
    assert_eq!(db.list_dataset_versions(id).unwrap().len(), versions);

    let all = db.query_rows(id, &RowQuery::default()).unwrap();
    let ns: Vec<&str> = all.iter().map(|row| row["n"].as_str()).collect();
    assert_eq!(ns, ["1", "2", "3", "4"]);

    let filtered = db
        .query_rows(
            id,
            &RowQuery {
                filters: vec![RowFilter {
                    column: "kind".into(),
                    op: "eq".into(),
                    value: "a".into(),
                }],
                columns: vec!["n".into()],
                limit: 2,
                offset: 1,
            },
        )
        .unwrap();
    assert_eq!(
        filtered,
        [
            HashMap::from([("n".to_string(), "3".to_string())]),
            HashMap::from([("n".to_string(), "4".to_string())]),
        ]
    );
    // An omitted operator means equality on both backends.
    let implicit = db
        .query_rows(
            id,
            &RowQuery {
                filters: vec![RowFilter {
                    column: "kind".into(),
                    op: String::new(),
                    value: "b".into(),
                }],
                ..RowQuery::default()
            },
        )
        .unwrap();
    assert_eq!(implicit, [row("b", "2")]);
}

#[test]
fn sqlite_dataset_rows_backend_conformance() {
    exercise(&RuntimeDb::memory(), "rows");
}

#[test]
#[ignore = "requires SEKAI_TEST_POSTGRES_URL for an isolated TLS PostgreSQL database"]
fn postgres_dataset_rows_backend_conformance() {
    let scratch = ScratchDatabase::create();
    let db = RuntimeDb::Postgres(Arc::new(scratch.connect(8)));
    exercise(&db, &format!("rows-{}", uuid::Uuid::new_v4().simple()));
}
