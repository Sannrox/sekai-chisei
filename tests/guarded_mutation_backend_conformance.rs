use sekai_chisei::db::graph::GraphBackend;
use sekai_chisei::db::guarded_mutation::GuardedMutationBackend;
use sekai_chisei::db::lease::LeaseBackend;
use sekai_chisei::db::{postgres::PostgresDb, sekai::SekaiDb};
use sekai_chisei::domain::Object;
use sekai_chisei::sekai::lease::LeaseError;
use std::collections::HashMap;
use std::sync::{Arc, Barrier};

trait GuardedHarness: LeaseBackend + GuardedMutationBackend + GraphBackend {}
impl GuardedHarness for SekaiDb {}
impl GuardedHarness for PostgresDb {}

fn object(id: &str, name: &str, namespace: &str) -> Object {
    Object {
        id: id.into(),
        kind: "component".into(),
        name: name.into(),
        namespace: namespace.into(),
        external_id: String::new(),
        properties: HashMap::new(),
        created: 1,
        updated: 1,
    }
}

fn exercise(db: &dyn GuardedHarness, prefix: &str) {
    let namespace = format!("{prefix}-ns");
    let key = format!("{prefix}-key");
    let object_id = format!("{prefix}-obj");
    let lease = db
        .acquire_lease(
            &namespace, &key, "worker-a", 100, "lease-1", "actor-a", "local", 10,
        )
        .unwrap();
    let original = object(&object_id, "original", &namespace);

    let created = db
        .guarded_create_object(
            &original,
            &namespace,
            &key,
            &lease.fencing_token,
            "create-1",
            "actor-a",
            11,
        )
        .unwrap();
    assert_eq!(created.name, "original");
    assert_eq!(db.get_object(&object_id).unwrap().unwrap().name, "original");
    assert_eq!(
        db.guarded_create_object(
            &original,
            &namespace,
            &key,
            &lease.fencing_token,
            "create-1",
            "actor-a",
            12,
        )
        .unwrap()
        .name,
        "original"
    );

    let mut conflict = original.clone();
    conflict.name = "conflict".into();
    assert!(matches!(
        db.guarded_create_object(
            &conflict,
            &namespace,
            &key,
            &lease.fencing_token,
            "create-1",
            "actor-a",
            13,
        ),
        Err(LeaseError::Conflict(_))
    ));

    let mut updated = original.clone();
    updated.name = "updated".into();
    updated.updated = 2;
    let committed = db
        .guarded_update_object(
            &updated,
            &updated,
            Some(&original),
            &namespace,
            &key,
            &lease.fencing_token,
            "update-1",
            "actor-a",
            14,
        )
        .unwrap();
    assert_eq!(committed.name, "updated");
    assert_eq!(
        db.guarded_update_object(
            &updated,
            &updated,
            None,
            &namespace,
            &key,
            &lease.fencing_token,
            "update-1",
            "actor-a",
            15,
        )
        .unwrap()
        .name,
        "updated"
    );

    let mut mismatched = updated.clone();
    mismatched.namespace = format!("{namespace}-other");
    assert!(matches!(
        db.guarded_update_object(
            &mismatched,
            &mismatched,
            Some(&updated),
            &namespace,
            &key,
            &lease.fencing_token,
            "namespace-mismatch",
            "actor-a",
            16,
        ),
        Err(LeaseError::Mutation(message)) if message == "object namespace is immutable"
    ));
    assert_eq!(
        db.get_object(&object_id).unwrap().unwrap().namespace,
        namespace
    );

    let mut stale_snapshot = updated.clone();
    stale_snapshot.name = "stale".into();
    assert!(matches!(
        db.guarded_update_object(
            &stale_snapshot,
            &stale_snapshot,
            Some(&original),
            &namespace,
            &key,
            &lease.fencing_token,
            "stale-auth",
            "actor-a",
            17,
        ),
        Err(LeaseError::Mutation(message)) if message == "object changed since authorization"
    ));
    assert!(matches!(
        db.guarded_update_object(
            &updated,
            &updated,
            None,
            &namespace,
            &key,
            &lease.fencing_token,
            "missing-snapshot",
            "actor-a",
            17,
        ),
        Err(LeaseError::Mutation(message)) if message == "not found"
    ));
    assert_eq!(db.get_object(&object_id).unwrap().unwrap().name, "updated");

    db.guarded_delete_object(
        &object_id,
        Some(&updated),
        &namespace,
        &key,
        &lease.fencing_token,
        "delete-1",
        "actor-a",
        18,
    )
    .unwrap();
    db.guarded_delete_object(
        &object_id,
        None,
        &namespace,
        &key,
        &lease.fencing_token,
        "delete-1",
        "actor-a",
        19,
    )
    .unwrap();
    assert!(db.get_object(&object_id).unwrap().is_none());
    let changes = db.list_object_changes(&object_id, 100, 0).unwrap();
    assert_eq!(
        changes
            .iter()
            .filter(|change| change.field == "_created")
            .count(),
        1
    );
    assert_eq!(
        changes
            .iter()
            .filter(|change| change.field == "_deleted")
            .count(),
        1
    );

    exercise_fencing(db, prefix);
}

fn exercise_fencing(db: &dyn GuardedHarness, prefix: &str) {
    let namespace = format!("{prefix}-fence");
    let key = format!("{prefix}-fence-key");
    let object_id = format!("{prefix}-fence-obj");
    let first = db
        .acquire_lease(
            &namespace, &key, "worker-a", 10, "lease-a", "actor-a", "local", 10,
        )
        .unwrap();
    let original = object(&object_id, "original", &namespace);
    db.guarded_create_object(
        &original,
        &namespace,
        &key,
        &first.fencing_token,
        "create",
        "actor-a",
        11,
    )
    .unwrap();

    let mut expired_update = original.clone();
    expired_update.name = "expired".into();
    assert!(matches!(
        db.guarded_update_object(
            &expired_update,
            &expired_update,
            Some(&original),
            &namespace,
            &key,
            &first.fencing_token,
            "expired-update",
            "actor-a",
            20,
        ),
        Err(LeaseError::Stale(_))
    ));

    let second = db
        .takeover_expired_lease(
            &namespace,
            &key,
            "worker-b",
            &first.fencing_token,
            20,
            10,
            "lease-b",
            "actor-b",
            "local",
            20,
        )
        .unwrap();
    assert!(matches!(
        db.guarded_delete_object(
            &object_id,
            Some(&original),
            &namespace,
            &key,
            &first.fencing_token,
            "stale-delete",
            "actor-a",
            21,
        ),
        Err(LeaseError::Stale(_))
    ));

    db.release_lease(
        &namespace,
        &key,
        &second.fencing_token,
        "release",
        "actor-b",
        "local",
        22,
    )
    .unwrap();
    assert!(matches!(
        db.guarded_update_object(
            &expired_update,
            &expired_update,
            Some(&original),
            &namespace,
            &key,
            &second.fencing_token,
            "released-update",
            "actor-b",
            23,
        ),
        Err(LeaseError::Stale(_))
    ));
    assert_eq!(db.get_object(&object_id).unwrap().unwrap().name, "original");
}

#[test]
fn sqlite_guarded_mutation_conformance() {
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
fn postgres_guarded_mutation_conformance_and_restart() {
    let prefix = format!("pg-{}", uuid::Uuid::new_v4().simple());
    exercise(&postgres(), &prefix);
    let restarted = postgres();
    let object_id = format!("{prefix}-obj");
    assert!(restarted.get_object(&object_id).unwrap().is_none());
    assert_eq!(
        restarted
            .list_object_changes(&object_id, 100, 0)
            .unwrap()
            .iter()
            .filter(|change| change.field == "_deleted")
            .count(),
        1
    );
}

#[test]
#[ignore = "requires SEKAI_TEST_POSTGRES_URL for an isolated TLS PostgreSQL database"]
fn postgres_guarded_update_and_takeover_have_one_serializable_order() {
    let db = Arc::new(postgres());
    let prefix = format!("race-{}", uuid::Uuid::new_v4().simple());
    let namespace = format!("{prefix}-ns");
    let key = format!("{prefix}-key");
    let object_id = format!("{prefix}-obj");
    let first = db
        .acquire_lease(
            &namespace, &key, "worker-a", 10, "lease-1", "actor-a", "local", 10,
        )
        .unwrap();
    let original = object(&object_id, "before", &namespace);
    GraphBackend::create_object(db.as_ref(), &original, "actor-a").unwrap();
    let barrier = Arc::new(Barrier::new(2));
    let update = {
        let db = Arc::clone(&db);
        let barrier = Arc::clone(&barrier);
        let token = first.fencing_token.clone();
        let namespace = namespace.clone();
        let key = key.clone();
        let object_id = object_id.clone();
        std::thread::spawn(move || {
            let value = object(&object_id, "updated", &namespace);
            barrier.wait();
            db.guarded_update_object(
                &value,
                &value,
                Some(&object(&object_id, "before", &namespace)),
                &namespace,
                &key,
                &token,
                "update",
                "actor-a",
                19,
            )
        })
    };
    let takeover = {
        let db = Arc::clone(&db);
        let barrier = Arc::clone(&barrier);
        let token = first.fencing_token.clone();
        let namespace = namespace.clone();
        let key = key.clone();
        std::thread::spawn(move || {
            barrier.wait();
            db.takeover_expired_lease(
                &namespace, &key, "worker-b", &token, 20, 10, "lease-2", "actor-b", "local", 20,
            )
        })
    };
    let update_result = update.join().unwrap();
    let replacement = takeover.join().unwrap().unwrap();
    assert_eq!(replacement.generation, 2);
    match update_result {
        Ok(_) => assert_eq!(db.get_object(&object_id).unwrap().unwrap().name, "updated"),
        Err(LeaseError::Stale(_)) => {
            assert_eq!(db.get_object(&object_id).unwrap().unwrap().name, "before")
        }
        other => panic!("unexpected guarded update outcome: {other:?}"),
    }
}
