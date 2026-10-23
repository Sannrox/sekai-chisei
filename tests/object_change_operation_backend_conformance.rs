//! Shared SQLite/PostgreSQL conformance for object change history with a
//! stored operation id per change (#1689).

use sekai_chisei::db::postgres::PostgresDb;
use sekai_chisei::db::sekai::SekaiDb;
use sekai_chisei::domain::Object;
use sekai_chisei::sekai::audit::ObjectChange;
use std::collections::HashMap;

trait ChangeHarness {
    fn create(&self, object: &Object, operation_id: &str) -> Result<(), String>;
    fn update(&self, object: &Object, operation_id: &str) -> Result<Option<Object>, String>;
    fn delete(&self, id: &str) -> Result<Option<Object>, String>;
    fn visible(&self, id: &str, limit: i32, offset: i32) -> Result<Vec<ObjectChange>, String>;
    fn all(&self, id: &str) -> Result<Vec<ObjectChange>, String>;
    fn kind(&self, id: &str) -> Result<Option<String>, String>;
    fn namespace(&self, id: &str) -> Result<Option<String>, String>;
}

macro_rules! harness {
    ($db:ty) => {
        impl ChangeHarness for $db {
            fn create(&self, object: &Object, operation_id: &str) -> Result<(), String> {
                self.create_object_for_operation(object, "conformance", operation_id)
            }
            fn update(
                &self,
                object: &Object,
                operation_id: &str,
            ) -> Result<Option<Object>, String> {
                self.update_object_for_operation(object, None, "conformance", operation_id)
            }
            fn delete(&self, id: &str) -> Result<Option<Object>, String> {
                self.delete_object_with_audit(id, "conformance")
            }
            fn visible(
                &self,
                id: &str,
                limit: i32,
                offset: i32,
            ) -> Result<Vec<ObjectChange>, String> {
                self.list_visible_object_changes(id, limit, offset)
            }
            fn all(&self, id: &str) -> Result<Vec<ObjectChange>, String> {
                self.list_object_changes(id, 100, 0)
            }
            fn kind(&self, id: &str) -> Result<Option<String>, String> {
                self.object_change_kind(id)
            }
            fn namespace(&self, id: &str) -> Result<Option<String>, String> {
                self.object_change_namespace(id)
            }
        }
    };
}
harness!(SekaiDb);
harness!(PostgresDb);

fn ticket(prefix: &str, title: &str, updated: i64) -> Object {
    Object {
        id: format!("{prefix}-ticket"),
        kind: "ticket".into(),
        name: "ticket".into(),
        namespace: format!("{prefix}-ns"),
        external_id: format!("{prefix}:ticket"),
        properties: HashMap::from([("title".into(), title.into())]),
        created: 10,
        updated,
    }
}

fn exercise(db: &dyn ChangeHarness, prefix: &str) {
    let id = format!("{prefix}-ticket");
    db.create(&ticket(prefix, "draft", 10), "op-create")
        .unwrap();
    // Written back to back, usually in the same millisecond, by another operation.
    db.update(&ticket(prefix, "final", 11), "op-update")
        .unwrap();
    db.update(&ticket(prefix, "edited", 12), "").unwrap();

    let all = db.all(&id).unwrap();
    let titles = all
        .iter()
        .filter(|change| change.field == "properties.title")
        .map(|change| (change.new_value.as_str(), change.operation_id.as_str()))
        .collect::<Vec<_>>();
    assert_eq!(titles, vec![("edited", ""), ("final", "op-update")]);
    let created = all
        .iter()
        .find(|change| change.field == "_created")
        .unwrap();
    assert_eq!(created.operation_id, "op-create");

    // Visible history hides the reserved namespace field and pages like SQLite.
    let visible = db.visible(&id, 100, 0).unwrap();
    assert!(visible.iter().all(|change| change.field != "_namespace"));
    assert!(visible.iter().any(|change| change.field == "_created"));
    let first = db.visible(&id, 1, 0).unwrap();
    let second = db.visible(&id, 1, 1).unwrap();
    assert_eq!(first.len(), 1);
    assert_eq!(first[0].id, visible[0].id);
    assert_eq!(second[0].id, visible[1].id);

    db.delete(&id).unwrap();
    assert_eq!(db.kind(&id).unwrap().as_deref(), Some("ticket"));
    assert_eq!(db.namespace(&id).unwrap(), Some(format!("{prefix}-ns")));
    assert_eq!(db.kind("never-existed").unwrap(), None);
    assert_eq!(db.namespace("never-existed").unwrap(), None);
}

#[test]
fn sqlite_object_change_operation_conformance() {
    exercise(&SekaiDb::new(":memory:").unwrap(), "sqlite");
}

#[test]
#[ignore = "requires SEKAI_TEST_POSTGRES_URL for an isolated TLS PostgreSQL database"]
fn postgres_object_change_operation_conformance() {
    let url = std::env::var("SEKAI_TEST_POSTGRES_URL")
        .expect("SEKAI_TEST_POSTGRES_URL must identify an isolated PostgreSQL database");
    let db = match std::env::var("SEKAI_TEST_POSTGRES_CA_CERT") {
        Ok(path) => {
            PostgresDb::connect_with_ca_certificate(&url, 8, &std::fs::read(path).unwrap()).unwrap()
        }
        Err(_) => PostgresDb::connect(&url, 8).unwrap(),
    };
    exercise(&db, &format!("pg-{}", uuid::Uuid::new_v4().simple()));
}
