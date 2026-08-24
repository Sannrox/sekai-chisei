use sekai_chisei::db::graph::GraphBackend;
use sekai_chisei::db::postgres::PostgresDb;
use sekai_chisei::db::sekai::SekaiDb;
use sekai_chisei::domain::{Direction, Link, ListFilter, Object, PropertyFilter};
use sekai_chisei::sekai::schema::{InterfaceDef, ObjectType};
use sekai_chisei::sekai::security::{Grant, Role};
use std::collections::HashMap;
use std::sync::{Arc, Barrier};

fn object(prefix: &str, id: &str, kind: &str, namespace: &str, updated: i64) -> Object {
    Object {
        id: format!("{prefix}-{id}"),
        kind: kind.into(),
        name: id.into(),
        namespace: namespace.into(),
        external_id: format!("{prefix}:{kind}:{id}"),
        properties: HashMap::from([("tier".into(), "core".into())]),
        created: 10,
        updated,
    }
}

fn exercise_graph_backend(db: &dyn GraphBackend, prefix: &str) {
    let namespace = format!("{prefix}-ns");
    let mut root = object(prefix, "root", "namespace", &namespace, 10);
    root.external_id = format!("namespace:{namespace}");
    root.properties.insert("team_managed".into(), "true".into());
    root.properties.insert("score".into(), "10".into());
    root.properties.insert("code".into(), "Alpha%".into());
    root.properties.insert("huge".into(), "1e999".into());
    let mut child = object(prefix, "child", "commit", &namespace, 10);
    child.properties.insert("score".into(), "2".into());
    child.properties.insert("code".into(), "Beta".into());
    db.create_object(&root, "conformance").unwrap();
    db.create_object(&child, "conformance").unwrap();
    let audit_count = db.list_object_changes(&root.id, 100, 0).unwrap().len();
    assert!(db.create_object(&root, "duplicate").is_err());
    assert_eq!(
        db.list_object_changes(&root.id, 100, 0).unwrap().len(),
        audit_count
    );

    let listed = db
        .list_objects(&ListFilter {
            namespace: Some(namespace.clone()),
            property_filters: vec![PropertyFilter {
                key: "tier".into(),
                op: "eq".into(),
                value: "core".into(),
            }],
            ..Default::default()
        })
        .unwrap();
    assert_eq!(listed.len(), 2);
    assert_eq!(db.get_object(&root.id).unwrap().unwrap().created, 10);
    assert_eq!(
        db.list_objects(&ListFilter {
            namespace: Some(namespace.clone()),
            property_filters: vec![PropertyFilter {
                key: "score".into(),
                op: "gt".into(),
                value: "5".into(),
            }],
            ..Default::default()
        })
        .unwrap()[0]
            .id,
        root.id
    );
    assert_eq!(
        db.list_objects(&ListFilter {
            namespace: Some(namespace.clone()),
            property_filters: vec![PropertyFilter {
                key: "code".into(),
                op: "prefix".into(),
                value: "Alpha%".into(),
            }],
            ..Default::default()
        })
        .unwrap()
        .len(),
        1
    );
    let ordered = db
        .list_objects(&ListFilter {
            namespace: Some(namespace.clone()),
            order_by: "property:score".into(),
            ..Default::default()
        })
        .unwrap();
    assert_eq!(
        ordered
            .iter()
            .map(|object| object.id.as_str())
            .collect::<Vec<_>>(),
        vec![child.id.as_str(), root.id.as_str()]
    );
    assert_eq!(
        db.list_objects(&ListFilter {
            namespace: Some(namespace.clone()),
            order_by: "property:huge".into(),
            ..Default::default()
        })
        .unwrap()[0]
            .id,
        root.id
    );

    let interface_name = format!("{prefix}-Traceable");
    db.upsert_interface(&InterfaceDef {
        name: interface_name.clone(),
        description: "traceable".into(),
        properties: vec![],
        is_builtin: false,
    })
    .unwrap();
    db.upsert_object_type(&ObjectType {
        kind: "commit".into(),
        description: "commit".into(),
        properties: vec![],
        is_builtin: false,
        implements: vec![interface_name.clone()],
    })
    .unwrap();
    assert!(db.get_object_type("commit").unwrap().is_some());
    assert!(
        db.list_interfaces()
            .unwrap()
            .iter()
            .any(|interface| interface.name == interface_name)
    );
    assert_eq!(
        db.list_objects(&ListFilter {
            namespace: Some(namespace.clone()),
            interface_filter: vec![interface_name],
            ..Default::default()
        })
        .unwrap()
        .len(),
        1
    );

    let link = Link {
        id: format!("{prefix}-link"),
        from_id: root.id.clone(),
        to_id: child.id.clone(),
        relation: "produces".into(),
        created: 11,
    };
    assert!(db.create_link(&link).unwrap());
    assert!(!db.create_link(&link).unwrap());
    assert_eq!(
        db.get_links(&root.id, "produces", &Direction::Outgoing)
            .unwrap()
            .len(),
        1
    );
    assert_eq!(db.lineage(&root.id, 10).unwrap().nodes.len(), 2);

    let viewer = format!("{prefix}-viewer");
    db.create_grant(&Grant {
        id: format!("{prefix}-grant"),
        object_id: root.id.clone(),
        principal: viewer.clone(),
        role: Role::Viewer,
        created: 13,
    })
    .unwrap();
    assert!(db.can_access(&root.id, &[&viewer]).unwrap());
    assert!(!db.can_write(&root.id, &[&viewer]).unwrap());
    assert!(db.can_access(&child.id, &[&viewer]).unwrap());
    assert!(!db.can_access(&root.id, &["other"]).unwrap());
    assert!(!db.can_access(&child.id, &["other"]).unwrap());
    assert!(!db.can_access("missing", &[&viewer]).unwrap());
    assert_eq!(
        db.list_objects_for_principals(
            &ListFilter {
                namespace: Some(namespace),
                ..Default::default()
            },
            &["other"]
        )
        .unwrap()
        .0
        .len(),
        0
    );

    let mut invalid_created = root.clone();
    invalid_created.created = 11;
    invalid_created.updated = 19;
    assert!(
        db.update_object(&invalid_created, "conformance", 10)
            .unwrap_err()
            .contains("created timestamp")
    );

    root.name = "renamed".into();
    root.updated = 20;
    assert!(
        db.update_object(&root, "conformance", 10)
            .unwrap()
            .is_some()
    );
    let changes = db.list_object_changes(&root.id, 100, 0).unwrap();
    assert!(changes.iter().any(|change| change.field == "_created"));
    assert!(changes.iter().any(|change| change.field == "name"));

    assert!(
        db.delete_object(&child.id, "conformance")
            .unwrap()
            .is_some()
    );
    assert!(db.get_object(&child.id).unwrap().is_none());
    assert!(
        db.list_object_changes(&child.id, 100, 0)
            .unwrap()
            .iter()
            .any(|change| change.field == "_deleted")
    );
}

#[test]
fn sqlite_core_graph_conformance() {
    let db = SekaiDb::new(":memory:").unwrap();
    exercise_graph_backend(&db, "sqlite");
}

fn postgres_test_database() -> PostgresDb {
    let url = std::env::var("SEKAI_TEST_POSTGRES_URL")
        .expect("SEKAI_TEST_POSTGRES_URL must identify an isolated PostgreSQL database");
    PostgresDb::connect(&url, 8).unwrap()
}

#[test]
#[ignore = "requires SEKAI_TEST_POSTGRES_URL for an isolated TLS PostgreSQL database"]
fn postgres_core_graph_conformance() {
    let db = postgres_test_database();
    exercise_graph_backend(&db, &format!("pg-{}", uuid::Uuid::new_v4().simple()));
}

#[test]
#[ignore = "requires SEKAI_TEST_POSTGRES_URL for an isolated TLS PostgreSQL database"]
fn postgres_conflicting_updates_do_not_lose_a_revision() {
    let db = Arc::new(postgres_test_database());
    let prefix = format!("race-{}", uuid::Uuid::new_v4().simple());
    let original = object(&prefix, "object", "component", "race", 10);
    db.create_object_with_audit(&original, "conformance")
        .unwrap();
    let barrier = Arc::new(Barrier::new(3));
    let handles = ["first", "second"].map(|name| {
        let db = db.clone();
        let barrier = barrier.clone();
        let mut candidate = original.clone();
        candidate.name = name.into();
        candidate.updated = 11;
        std::thread::spawn(move || {
            barrier.wait();
            db.update_object_with_audit_if_revision(&candidate, name, 10, None)
        })
    });
    barrier.wait();
    let results = handles.map(|handle| handle.join().unwrap());
    assert_eq!(results.iter().filter(|result| result.is_ok()).count(), 1);
    assert_eq!(
        results
            .iter()
            .filter(|result| result
                .as_ref()
                .is_err_and(|error| error.contains("revision conflict")))
            .count(),
        1
    );
}
