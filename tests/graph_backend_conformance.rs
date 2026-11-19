use sekai_chisei::db::graph::GraphBackend;
use sekai_chisei::db::postgres::PostgresDb;
use sekai_chisei::db::sekai::SekaiDb;
use sekai_chisei::domain::{Direction, Link, ListFilter, Object, PropertyFilter};
use sekai_chisei::sekai::object_security::PrincipalPolicyContext;
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
        ..Default::default()
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

fn exercise_batch_object_read(db: &dyn GraphBackend, prefix: &str) {
    let namespace = format!("{prefix}-batch-ns");
    let visible = object(prefix, "batch-visible", "component", &namespace, 10);
    let restricted = object(prefix, "batch-restricted", "component", &namespace, 10);
    db.create_object(&visible, "conformance").unwrap();
    db.create_object(&restricted, "conformance").unwrap();
    db.create_grant(&Grant {
        id: format!("{prefix}-batch-grant"),
        object_id: restricted.id.clone(),
        principal: "batch-owner".into(),
        role: Role::Viewer,
        created: 11,
        ..Default::default()
    })
    .unwrap();

    let ids = vec![
        visible.id.clone(),
        restricted.id,
        format!("{prefix}-batch-missing"),
        visible.id.clone(),
    ];
    let listed = db
        .list_objects_by_ids_with_policy_context(
            &ids,
            &["batch-reader"],
            &PrincipalPolicyContext::default(),
        )
        .unwrap();
    assert_eq!(
        listed
            .iter()
            .map(|object| object.id.as_str())
            .collect::<Vec<_>>(),
        vec![visible.id.as_str()]
    );
}

/// Grant expiry, the strict admin role set, the team-managed namespace gate
/// and the `root`/`local` bypass of that gate.
fn exercise_authorization(db: &dyn GraphBackend, prefix: &str) {
    let grant = |id: &str, object_id: &str, principal: &str, role: Role, not_after_ms: i64| {
        db.create_grant(&Grant {
            id: format!("{prefix}-{id}"),
            object_id: object_id.into(),
            principal: principal.into(),
            role,
            created: 13,
            not_after_ms,
            ..Default::default()
        })
        .unwrap();
    };

    // An ungranted object is open to read and write but never to admin.
    let open_namespace = format!("{prefix}-open");
    let open = object(prefix, "open", "component", &open_namespace, 10);
    db.create_object(&open, "conformance").unwrap();
    assert!(db.can_access(&open.id, &["stranger"]).unwrap());
    assert!(db.can_write(&open.id, &["stranger"]).unwrap());
    assert!(!db.can_admin(&open.id, &["stranger"]).unwrap());

    // Once granted, only live grants count, and admin needs the admin role.
    let granted = object(prefix, "granted", "component", &open_namespace, 10);
    db.create_object(&granted, "conformance").unwrap();
    grant("viewer", &granted.id, "viewer", Role::Viewer, 0);
    grant("admin", &granted.id, "admin", Role::Admin, 0);
    grant("expired", &granted.id, "expired", Role::Admin, 1);
    assert!(db.can_access(&granted.id, &["viewer"]).unwrap());
    assert!(!db.can_write(&granted.id, &["viewer"]).unwrap());
    assert!(!db.can_admin(&granted.id, &["viewer"]).unwrap());
    assert!(db.can_admin(&granted.id, &["admin"]).unwrap());
    assert!(!db.can_access(&granted.id, &["expired"]).unwrap());
    assert!(!db.can_admin(&granted.id, &["expired"]).unwrap());
    assert!(!db.can_access(&granted.id, &["stranger"]).unwrap());
    // The privileged bypass covers the namespace gate, not object grants.
    assert!(!db.can_access(&granted.id, &["root"]).unwrap());

    // A team-managed namespace admits only principals with a live namespace
    // grant, or a privileged principal.
    let team_namespace = format!("{prefix}-team");
    let mut boundary = object(prefix, "team", "namespace", &team_namespace, 10);
    boundary.external_id = format!("namespace:{team_namespace}");
    boundary
        .properties
        .insert("team_managed".into(), "true".into());
    db.create_object(&boundary, "conformance").unwrap();
    let inside = object(prefix, "inside", "component", &team_namespace, 10);
    db.create_object(&inside, "conformance").unwrap();
    grant("member", &boundary.id, "member", Role::Viewer, 0);
    grant("former", &boundary.id, "former", Role::Viewer, 1);
    assert!(db.can_access(&inside.id, &["member"]).unwrap());
    assert!(!db.can_access(&inside.id, &["outsider"]).unwrap());
    assert!(!db.can_access(&inside.id, &["former"]).unwrap());
    assert!(db.can_access(&inside.id, &["root"]).unwrap());
    assert!(db.can_access(&inside.id, &["local"]).unwrap());
}

#[test]
fn sqlite_core_graph_conformance() {
    let db = SekaiDb::new(":memory:").unwrap();
    exercise_graph_backend(&db, "sqlite");
    exercise_batch_object_read(&db, "sqlite");
    exercise_authorization(&db, "sqlite");
}

fn postgres_test_database() -> PostgresDb {
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
fn postgres_core_graph_conformance() {
    let db = postgres_test_database();
    let prefix = format!("pg-{}", uuid::Uuid::new_v4().simple());
    exercise_graph_backend(&db, &prefix);
    exercise_batch_object_read(&db, &prefix);
    exercise_authorization(&db, &prefix);
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
            db.update_object_with_audit_if_revision(&candidate, name, 10, None, None)
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

    // The stored object and its change log both belong to the winner.
    let winner = if results[0].is_ok() {
        "first"
    } else {
        "second"
    };
    let stored = db.get_object(&original.id).unwrap().unwrap();
    assert_eq!(stored.name, winner);
    assert_eq!(stored.updated, 11);
    let renames: Vec<_> = db
        .list_object_changes(&original.id, 100, 0)
        .unwrap()
        .into_iter()
        .filter(|change| change.field == "name")
        .collect();
    assert_eq!(renames.len(), 1, "{renames:?}");
    assert_eq!(renames[0].new_value, winner);
    assert_eq!(renames[0].changed_by, winner);
}
