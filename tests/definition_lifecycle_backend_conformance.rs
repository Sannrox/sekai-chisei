use sekai_chisei::db::function::FunctionBackend;
use sekai_chisei::db::graph::GraphBackend;
use sekai_chisei::db::{postgres::PostgresDb, sekai::SekaiDb};
use sekai_chisei::domain::Object;
use sekai_chisei::sekai::function::{FuncParam, Function, OperatorStep, PipelineStep};
use sekai_chisei::sekai::schema::{InterfaceDef, ObjectType, PropertyDef, PropertyType};
use std::collections::HashMap;

trait DefinitionHarness: FunctionBackend + GraphBackend {}
impl DefinitionHarness for SekaiDb {}
impl DefinitionHarness for PostgresDb {}

fn function(name: &str) -> Function {
    Function {
        name: name.into(),
        description: "sum related components".into(),
        params: vec![FuncParam {
            name: "root".into(),
            param_type: "string".into(),
            required: true,
        }],
        pipeline: vec![
            PipelineStep::Operator(OperatorStep {
                op: "filter".into(),
                kind: "component".into(),
                property: String::new(),
                value: String::new(),
                relation: String::new(),
                dir: String::new(),
                func: String::new(),
                field: String::new(),
                alias: String::new(),
            }),
            PipelineStep::Operator(OperatorStep {
                op: "aggregate".into(),
                kind: String::new(),
                property: String::new(),
                value: String::new(),
                relation: String::new(),
                dir: String::new(),
                func: "count".into(),
                field: "id".into(),
                alias: "n".into(),
            }),
        ],
        created: 10,
    }
}

fn prop(name: &str) -> PropertyDef {
    PropertyDef {
        name: name.into(),
        prop_type: PropertyType::String,
        required: true,
        description: String::new(),
        enum_values: vec![],
        link_kind: String::new(),
        compute_expr: String::new(),
        classification: "public".into(),
        struct_fields: vec![],
    }
}

fn exercise_functions(db: &dyn DefinitionHarness, prefix: &str) {
    let alpha = function(&format!("{prefix}-alpha"));
    let beta = function(&format!("{prefix}-beta"));
    db.create_function(&alpha).unwrap();
    db.create_function(&beta).unwrap();
    assert!(
        db.create_function(&alpha).is_err(),
        "duplicates fail closed"
    );

    // A fresh name, so only the invalid field can refuse the create.
    let mut corrupt = function(&format!("{prefix}-corrupt"));
    corrupt.pipeline.clear();
    assert_eq!(
        db.create_function(&corrupt).unwrap_err(),
        "pipeline must have at least one step",
        "corrupt definitions fail closed"
    );
    assert!(db.get_function(&corrupt.name).unwrap().is_none());
    let nameless = function("");
    assert_eq!(
        db.create_function(&nameless).unwrap_err(),
        "function name required"
    );

    let listed = db.list_functions().unwrap();
    let names = listed
        .iter()
        .map(|function| function.name.as_str())
        .filter(|name| name.starts_with(prefix))
        .collect::<Vec<_>>();
    assert_eq!(names, vec![alpha.name.as_str(), beta.name.as_str()]);
    assert_eq!(
        db.get_function(&alpha.name).unwrap().unwrap().description,
        alpha.description
    );
}

fn exercise_schema_lifecycle(db: &dyn DefinitionHarness, prefix: &str) {
    let interface_name = format!("{prefix}-Trackable");
    let kind = format!("{prefix}-widget");
    let interface = InterfaceDef {
        name: interface_name.clone(),
        description: "trackable".into(),
        properties: vec![prop("tracking_id")],
        is_builtin: false,
    };
    db.upsert_interface(&interface).unwrap();
    assert_eq!(
        db.list_interfaces()
            .unwrap()
            .into_iter()
            .filter(|item| item.name == interface_name)
            .count(),
        1
    );

    let object_type = ObjectType {
        kind: kind.clone(),
        description: "widget".into(),
        properties: vec![prop("tracking_id")],
        is_builtin: false,
        implements: vec![interface_name.clone()],
    };
    db.upsert_object_type(&object_type).unwrap();
    assert_eq!(
        db.get_object_type(&kind).unwrap().unwrap().implements,
        vec![interface_name.clone()]
    );
    assert!(
        db.delete_interface(&interface_name)
            .unwrap_err()
            .contains("implement"),
        "referenced interfaces fail closed"
    );

    assert!(
        db.delete_object_type("namespace")
            .unwrap_err()
            .contains("builtin")
    );
    assert!(
        db.delete_interface("RiskScored")
            .unwrap_err()
            .contains("builtin")
    );

    let object = Object {
        id: format!("{prefix}-obj"),
        kind: kind.clone(),
        name: "live".into(),
        namespace: format!("{prefix}-ns"),
        external_id: String::new(),
        properties: HashMap::from([("tracking_id".into(), "t-1".into())]),
        created: 1,
        updated: 1,
    };
    GraphBackend::create_object(db, &object, "actor").unwrap();
    assert!(
        db.delete_object_type(&kind)
            .unwrap_err()
            .contains("objects of that kind"),
        "schema types with instances fail closed"
    );
    GraphBackend::delete_object(db, &object.id, "actor").unwrap();
    assert!(db.delete_object_type(&kind).unwrap());
    assert!(db.get_object_type(&kind).unwrap().is_none());
    assert!(db.delete_interface(&interface_name).unwrap());
    assert!(
        db.list_interfaces()
            .unwrap()
            .into_iter()
            .all(|item| item.name != interface_name)
    );
    // deterministic listing remains ordered for remaining fixtures
    let listed_kinds = db
        .list_object_types()
        .unwrap()
        .into_iter()
        .map(|item| item.kind)
        .collect::<Vec<_>>();
    let mut sorted = listed_kinds.clone();
    sorted.sort();
    assert_eq!(listed_kinds, sorted);
}

#[test]
fn sqlite_definition_lifecycle_conformance() {
    let db = SekaiDb::new(":memory:").unwrap();
    exercise_functions(&db, "sqlite");
    exercise_schema_lifecycle(&db, "sqlite");
}

fn postgres() -> PostgresDb {
    let url = std::env::var("SEKAI_TEST_POSTGRES_URL")
        .expect("SEKAI_TEST_POSTGRES_URL must identify an isolated PostgreSQL database");
    if let Ok(path) = std::env::var("SEKAI_TEST_POSTGRES_CA_CERT") {
        PostgresDb::connect_with_ca_certificate(&url, 8, &std::fs::read(path).unwrap()).unwrap()
    } else {
        PostgresDb::connect(&url, 8).unwrap()
    }
}

#[test]
#[ignore = "requires SEKAI_TEST_POSTGRES_URL for an isolated TLS PostgreSQL database"]
fn postgres_definition_lifecycle_conformance_and_restart() {
    let prefix = format!("pg-{}", uuid::Uuid::new_v4().simple());
    exercise_functions(&postgres(), &prefix);
    exercise_schema_lifecycle(&postgres(), &prefix);
    let restarted = postgres();
    assert!(
        restarted
            .get_function(&format!("{prefix}-alpha"))
            .unwrap()
            .is_some()
    );
    assert!(
        restarted
            .get_object_type(&format!("{prefix}-widget"))
            .unwrap()
            .is_none()
    );
    assert!(
        restarted
            .list_interfaces()
            .unwrap()
            .into_iter()
            .all(|item| item.name != format!("{prefix}-Trackable"))
    );
}

/// Runs `op` on a thread while `blocker` holds an open transaction, waits until
/// `op` waits on a lock or returns, then commits `blocker` and returns `op`'s result.
fn race_against_open_transaction<T: Send + 'static>(
    db: &PostgresDb,
    blocker: postgres::Transaction<'_>,
    op: impl FnOnce() -> T + Send + 'static,
) -> T {
    let handle = std::thread::spawn(op);
    let mut probe = db.connection().unwrap();
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(10);
    while !handle.is_finished() {
        let waiting: i64 = probe
            .query_one(
                "SELECT COUNT(*) FROM pg_stat_activity
                 WHERE datname = current_database() AND wait_event_type = 'Lock'",
                &[],
            )
            .unwrap()
            .get(0);
        if waiting > 0 {
            break;
        }
        assert!(
            std::time::Instant::now() < deadline,
            "racing operation neither waited nor returned"
        );
        std::thread::sleep(std::time::Duration::from_millis(20));
    }
    blocker.commit().unwrap();
    handle.join().unwrap()
}

#[test]
#[ignore = "requires SEKAI_TEST_POSTGRES_URL for an isolated TLS PostgreSQL database"]
fn postgres_schema_deletes_never_commit_alongside_a_racing_dependent_write() {
    let prefix = format!("pg-{}", uuid::Uuid::new_v4().simple());
    let db = std::sync::Arc::new(postgres());
    let kind = format!("{prefix}-raced");
    let interface_name = format!("{prefix}-Raced");
    db.upsert_interface(&InterfaceDef {
        name: interface_name.clone(),
        description: "raced".into(),
        properties: vec![],
        is_builtin: false,
    })
    .unwrap();
    let object_type = |kind: &str, implements: Vec<String>| ObjectType {
        kind: kind.into(),
        description: "raced".into(),
        properties: vec![],
        is_builtin: false,
        implements,
    };
    db.upsert_object_type(&object_type(&kind, vec![])).unwrap();

    // An uncommitted object insert of the kind: the delete waits, then refuses.
    let mut conn = db.connection().unwrap();
    let mut tx = conn.transaction().unwrap();
    tx.execute(
        "INSERT INTO sekai_objects (id, kind, name, namespace, external_id, properties, created, updated)
         VALUES ($1, $2, 'raced', 'default', '', '{}', 1, 1)",
        &[&format!("{prefix}-object"), &kind],
    )
    .unwrap();
    let (racer, raced) = (db.clone(), kind.clone());
    let deleted = race_against_open_transaction(&db, tx, move || racer.delete_object_type(&raced));
    assert!(
        deleted.unwrap_err().contains("objects of that kind exist"),
        "a type delete never commits beside a racing object insert"
    );

    // An uncommitted type upsert implementing the interface: the delete waits, then refuses.
    let mut tx = conn.transaction().unwrap();
    tx.execute(
        "INSERT INTO sekai_object_types (kind, description, properties_json, implements_json, created, updated)
         VALUES ($1, 'raced', '[]', $2, 1, 1)",
        &[&format!("{prefix}-late"), &serde_json::json!([interface_name]).to_string()],
    )
    .unwrap();
    let (racer, raced) = (db.clone(), interface_name.clone());
    let deleted = race_against_open_transaction(&db, tx, move || racer.delete_interface(&raced));
    assert!(
        deleted.unwrap_err().contains("implement"),
        "an interface delete never commits beside a racing implementing upsert"
    );

    // A delete already under way: the upsert waits, then fails as an unknown interface.
    let mut tx = conn.transaction().unwrap();
    tx.batch_execute("LOCK TABLE sekai_object_types IN SHARE MODE")
        .unwrap();
    tx.execute(
        "DELETE FROM sekai_object_types WHERE kind = $1",
        &[&format!("{prefix}-late")],
    )
    .unwrap();
    tx.execute(
        "DELETE FROM sekai_interfaces WHERE name = $1",
        &[&interface_name],
    )
    .unwrap();
    let (racer, upserted) = (
        db.clone(),
        object_type(&format!("{prefix}-after"), vec![interface_name.clone()]),
    );
    let upsert =
        race_against_open_transaction(&db, tx, move || racer.upsert_object_type(&upserted));
    assert_eq!(
        upsert.unwrap_err(),
        format!("unknown interface: {interface_name}")
    );
    assert!(
        db.get_object_type(&format!("{prefix}-after"))
            .unwrap()
            .is_none()
    );
}
