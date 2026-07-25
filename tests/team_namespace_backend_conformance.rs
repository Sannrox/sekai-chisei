use sekai_chisei::db::graph::GraphBackend;
use sekai_chisei::db::team_namespace::TeamNamespaceBackend;
use sekai_chisei::db::{postgres::PostgresDb, sekai::SekaiDb};
use sekai_chisei::domain::Object;
use sekai_chisei::sekai::security::Role;
use std::collections::HashMap;
use std::sync::{Arc, Barrier};

trait TeamNamespaceHarness: TeamNamespaceBackend + GraphBackend {}
impl TeamNamespaceHarness for SekaiDb {}
impl TeamNamespaceHarness for PostgresDb {}

fn exercise(db: &dyn TeamNamespaceHarness, prefix: &str) {
    let namespace = format!("{prefix}-acme");
    let principal = format!("{prefix}-alice");

    assert!(
        db.ensure_team_namespace("", &principal, Role::Viewer, "local")
            .unwrap_err()
            .contains("malformed namespace")
    );
    assert!(
        db.ensure_team_namespace(&namespace, "", Role::Viewer, "local")
            .unwrap_err()
            .contains("malformed principal")
    );
    assert!(
        db.ensure_team_namespace("tenant:x", &principal, Role::Viewer, "local")
            .unwrap_err()
            .contains("tenant identities")
    );
    assert!(
        db.ensure_team_namespace(&namespace, "tenant:x", Role::Viewer, "local")
            .unwrap_err()
            .contains("tenant identities")
    );
    assert!(db.find_namespace_boundary(&namespace).unwrap().is_none());

    let (created, grants) = db
        .ensure_team_namespace(&namespace, &principal, Role::Viewer, "local")
        .unwrap();
    assert_eq!(created.id, format!("namespace:{namespace}"));
    assert_eq!(created.external_id, format!("namespace:{namespace}"));
    assert_eq!(
        created.properties.get("team_managed").map(String::as_str),
        Some("true")
    );
    assert_eq!(grants.len(), 3);
    assert!(db.is_team_principal(&principal).unwrap());
    let principals = db
        .list_grants(&created.id)
        .unwrap()
        .into_iter()
        .map(|grant| grant.principal)
        .collect::<Vec<_>>();
    assert!(principals.contains(&"root".into()));
    assert!(principals.contains(&"local".into()));
    assert!(principals.contains(&principal));
    let changes = db.list_object_changes(&created.id, 100, 0).unwrap();
    assert!(
        changes.iter().any(|change| change.field == "_created"),
        "namespace bootstrap must leave object-change audit evidence"
    );

    // exact retry is idempotent
    let (again, grants_again) = db
        .ensure_team_namespace(&namespace, &principal, Role::Viewer, "local")
        .unwrap();
    assert_eq!(again.id, created.id);
    assert_eq!(grants_again.len(), 3);

    // role upgrade for same principal is reflected
    let (_, upgraded) = db
        .ensure_team_namespace(&namespace, &principal, Role::Admin, "local")
        .unwrap();
    assert!(
        upgraded
            .iter()
            .any(|grant| grant.principal == principal && grant.role == Role::Admin)
    );

    // duplicate canonical namespace identities fail closed
    let conflict_namespace = format!("{prefix}-conflict");
    let conflict_external = format!("namespace:{conflict_namespace}");
    for suffix in ["a", "b"] {
        GraphBackend::create_object(
            db,
            &Object {
                id: format!("{prefix}-dup-{suffix}"),
                kind: "namespace".into(),
                name: conflict_namespace.clone(),
                namespace: conflict_namespace.clone(),
                external_id: conflict_external.clone(),
                properties: HashMap::new(),
                created: 1,
                updated: 1,
            },
            "local",
        )
        .unwrap();
    }
    assert!(
        db.ensure_team_namespace(
            &conflict_namespace,
            &format!("{prefix}-bob"),
            Role::Viewer,
            "local"
        )
        .unwrap_err()
        .contains("not uniquely held")
    );

    // adopt legacy namespace boundary without grants
    let legacy = format!("{prefix}-legacy");
    let legacy_id = format!("namespace:{legacy}");
    GraphBackend::create_object(
        db,
        &Object {
            id: legacy_id.clone(),
            kind: "namespace".into(),
            name: legacy.clone(),
            namespace: String::new(),
            external_id: legacy_id.clone(),
            properties: HashMap::new(),
            created: 1,
            updated: 1,
        },
        "local",
    )
    .unwrap();
    let (adopted, adopted_grants) = db
        .ensure_team_namespace(&legacy, &format!("{prefix}-carol"), Role::Editor, "local")
        .unwrap();
    assert_eq!(adopted.namespace, legacy);
    assert_eq!(
        adopted.properties.get("team_managed").map(String::as_str),
        Some("true")
    );
    assert_eq!(adopted_grants.len(), 3);

    // orphan grants without boundary fail closed
    let orphan = format!("{prefix}-orphan");
    let orphan_id = format!("namespace:{orphan}");
    db.create_grant(&sekai_chisei::sekai::security::Grant {
        id: format!("orphan-{prefix}"),
        object_id: orphan_id,
        principal: "root".into(),
        role: Role::Admin,
        created: 1,
    })
    .unwrap();
    assert!(
        db.ensure_team_namespace(&orphan, &format!("{prefix}-dave"), Role::Viewer, "local")
            .unwrap_err()
            .contains("grants without a namespace boundary")
    );
}

#[test]
fn sqlite_team_namespace_conformance() {
    let db = SekaiDb::new(":memory:").unwrap();
    exercise(&db, "sqlite");
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
fn postgres_team_namespace_conformance_and_restart() {
    let prefix = format!("pg-{}", uuid::Uuid::new_v4().simple());
    exercise(&postgres(), &prefix);
    let restarted = postgres();
    let namespace = format!("{prefix}-acme");
    assert!(
        restarted
            .find_namespace_boundary(&namespace)
            .unwrap()
            .is_some()
    );
    assert!(
        restarted
            .is_team_principal(&format!("{prefix}-alice"))
            .unwrap()
    );
}

#[test]
#[ignore = "requires SEKAI_TEST_POSTGRES_URL for an isolated TLS PostgreSQL database"]
fn postgres_concurrent_team_namespace_creation_has_one_boundary() {
    let db = Arc::new(postgres());
    let prefix = format!("race-{}", uuid::Uuid::new_v4().simple());
    let namespace = format!("{prefix}-ns");
    let barrier = Arc::new(Barrier::new(3));
    let handles = ["alice", "bob"].map(|principal| {
        let db = Arc::clone(&db);
        let barrier = Arc::clone(&barrier);
        let namespace = namespace.clone();
        let principal = format!("{prefix}-{principal}");
        std::thread::spawn(move || {
            barrier.wait();
            db.ensure_team_namespace(&namespace, &principal, Role::Viewer, "local")
        })
    });
    barrier.wait();
    let results = handles.map(|handle| handle.join().unwrap());
    assert!(results.iter().all(|result| result.is_ok()));
    let boundary = db.find_namespace_boundary(&namespace).unwrap().unwrap();
    assert_eq!(boundary.kind, "namespace");
    assert_eq!(db.list_grants(&boundary.id).unwrap().len(), 4); // root, local, alice, bob
}
