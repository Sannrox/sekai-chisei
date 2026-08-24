use std::collections::{BTreeMap, HashMap};
use std::sync::{Arc, Barrier};

use sekai_chisei::db::postgres::PostgresDb;
use sekai_chisei::db::runtime_db::RuntimeDb;
use sekai_chisei::db::sekai::SekaiDb;
use sekai_chisei::domain::{KIND_CAPABILITY, ListFilter, Object, PropertyFilter};
use sekai_chisei::sekai::object_security::{
    OBJECT_SECURITY_POLICY_VERSION, ObjectSecurityOperation, ObjectSecurityPolicy,
    ObjectSecurityPredicate, ObjectSecurityRule, PrincipalPolicyContext,
};

fn policy(
    namespace: &str,
    kind: &str,
    predicates: Vec<ObjectSecurityPredicate>,
) -> ObjectSecurityPolicy {
    ObjectSecurityPolicy {
        contract_version: OBJECT_SECURITY_POLICY_VERSION.into(),
        namespace: namespace.into(),
        kind: kind.into(),
        rules: vec![ObjectSecurityRule {
            operation: ObjectSecurityOperation::Read,
            predicates,
        }],
    }
}

fn object_id(namespace: &str, id: &str) -> String {
    format!("{namespace}:{id}")
}

fn object(namespace: &str, id: &str, name: &str, owner: &str, state: &str) -> Object {
    Object {
        id: object_id(namespace, id),
        kind: "document".into(),
        name: name.into(),
        namespace: namespace.into(),
        external_id: object_id(namespace, id),
        properties: HashMap::from([
            ("owner".into(), owner.into()),
            ("state".into(), state.into()),
        ]),
        created: 1,
        updated: 1,
    }
}

fn exercise(db: RuntimeDb, namespace: &str) {
    for candidate in [
        object(namespace, "a", "alpha", "alice", "open"),
        object(namespace, "b", "bravo", "bob", "open"),
        object(namespace, "c", "charlie", "alice", "closed"),
        object(namespace, "d", "delta", "alice", "open"),
    ] {
        db.create_object(&candidate).unwrap();
    }
    let mut missing_owner = object(namespace, "e", "echo", "ignored", "open");
    missing_owner.properties.remove("owner");
    db.create_object(&missing_owner).unwrap();

    let broad = policy(
        namespace,
        "document",
        vec![ObjectSecurityPredicate::AllowAll],
    );
    let broad_revision = db
        .put_object_security_policy(&broad, "root", "put-broad", 1)
        .unwrap();
    assert_eq!(
        db.put_object_security_policy(&broad, "root", "put-broad", 2)
            .unwrap(),
        broad_revision
    );
    let conflicting = policy(
        namespace,
        "document",
        vec![ObjectSecurityPredicate::PropertyEquals {
            property: "state".into(),
            value: "open".into(),
        }],
    );
    assert!(
        db.put_object_security_policy(&conflicting, "root", "put-broad", 3)
            .unwrap_err()
            .contains("idempotency_conflict")
    );

    let broad_map = BTreeMap::from([(
        "document".to_string(),
        broad_revision.revision_digest.clone(),
    )]);
    let broad_activation = db
        .activate_object_security_policies(namespace, &broad_map, "root", "activate-broad", 4)
        .unwrap();
    assert_eq!(
        db.activate_object_security_policies(namespace, &broad_map, "root", "activate-broad", 5)
            .unwrap(),
        broad_activation
    );
    assert_eq!(
        db.get_object_security_policy(namespace, &broad_revision.revision_digest)
            .unwrap()
            .unwrap(),
        broad_revision
    );
    assert_eq!(
        db.get_object_security_activation(namespace)
            .unwrap()
            .unwrap(),
        broad_activation
    );
    let empty = PrincipalPolicyContext::default();
    assert!(
        db.get_object_with_policy_context(&object_id(namespace, "b"), &empty)
            .unwrap()
            .is_some()
    );

    let owner = policy(
        namespace,
        "document",
        vec![ObjectSecurityPredicate::SubjectEqualsProperty {
            property: "owner".into(),
        }],
    );
    let owner_revision = db
        .put_object_security_policy(&owner, "root", "put-owner", 6)
        .unwrap();
    assert!(
        db.activate_object_security_policies(
            namespace,
            &BTreeMap::from([("document".into(), owner_revision.revision_digest.clone())]),
            "root",
            "activate-broad",
            7,
        )
        .unwrap_err()
        .contains("idempotency_conflict")
    );
    db.activate_object_security_policies(
        namespace,
        &BTreeMap::from([("document".into(), owner_revision.revision_digest.clone())]),
        "root",
        "activate-owner",
        8,
    )
    .unwrap();
    let alice = PrincipalPolicyContext {
        subjects: vec!["alice".into()],
        scopes: vec![],
    };
    assert!(
        db.get_object_with_policy_context(&object_id(namespace, "a"), &alice)
            .unwrap()
            .is_some()
    );
    assert!(
        db.get_object_with_policy_context(&object_id(namespace, "b"), &alice)
            .unwrap()
            .is_none()
    );
    assert!(
        db.get_object_with_policy_context(&object_id(namespace, "e"), &alice)
            .unwrap()
            .is_none()
    );

    let filter = ListFilter {
        namespace: Some(namespace.into()),
        kind: Some("document".into()),
        property_filters: vec![PropertyFilter {
            key: "state".into(),
            op: "eq".into(),
            value: "open".into(),
        }],
        order_by: "name".into(),
        offset: 1,
        limit: 1,
        ..Default::default()
    };
    let (rows, total) = db
        .list_objects_with_total_for_policy_context(&filter, &["alice"], &[], &alice)
        .unwrap();
    assert_eq!(total, 2);
    assert_eq!(
        rows.iter().map(|row| row.id.clone()).collect::<Vec<_>>(),
        vec![object_id(namespace, "d")]
    );

    let scoped = policy(
        namespace,
        "document",
        vec![
            ObjectSecurityPredicate::RequiredScopeEquals {
                value: "documents:read".into(),
            },
            ObjectSecurityPredicate::PropertyEquals {
                property: "state".into(),
                value: "open".into(),
            },
        ],
    );
    let scoped_revision = db
        .put_object_security_policy(&scoped, "root", "put-scoped", 9)
        .unwrap();
    db.activate_object_security_policies(
        namespace,
        &BTreeMap::from([("document".into(), scoped_revision.revision_digest)]),
        "root",
        "activate-scoped",
        10,
    )
    .unwrap();
    assert!(
        db.get_object_with_policy_context(&object_id(namespace, "a"), &empty)
            .unwrap()
            .is_none()
    );
    let authorized_scope = PrincipalPolicyContext {
        subjects: vec!["nobody".into()],
        scopes: vec!["documents:read".into()],
    };
    assert!(
        db.get_object_with_policy_context(&object_id(namespace, "a"), &authorized_scope)
            .unwrap()
            .is_some()
    );
    assert!(
        db.get_object_with_policy_context(&object_id(namespace, "c"), &authorized_scope)
            .unwrap()
            .is_none()
    );

    let write = ObjectSecurityPolicy {
        contract_version: OBJECT_SECURITY_POLICY_VERSION.into(),
        namespace: namespace.into(),
        kind: "document".into(),
        rules: vec![
            ObjectSecurityRule {
                operation: ObjectSecurityOperation::Read,
                predicates: vec![ObjectSecurityPredicate::AllowAll],
            },
            ObjectSecurityRule {
                operation: ObjectSecurityOperation::Update,
                predicates: vec![ObjectSecurityPredicate::SubjectEqualsProperty {
                    property: "owner".into(),
                }],
            },
            ObjectSecurityRule {
                operation: ObjectSecurityOperation::Delete,
                predicates: vec![ObjectSecurityPredicate::SubjectEqualsProperty {
                    property: "owner".into(),
                }],
            },
            ObjectSecurityRule {
                operation: ObjectSecurityOperation::Create,
                predicates: vec![ObjectSecurityPredicate::AllowAll],
            },
            ObjectSecurityRule {
                operation: ObjectSecurityOperation::Sync,
                predicates: vec![ObjectSecurityPredicate::AllowAll],
            },
        ],
    };
    let write_revision = db
        .put_object_security_policy(&write, "root", "put-write", 11)
        .unwrap();
    db.activate_object_security_policies(
        namespace,
        &BTreeMap::from([("document".into(), write_revision.revision_digest.clone())]),
        "root",
        "activate-write",
        12,
    )
    .unwrap();
    let loaded = db
        .active_object_policy(namespace, "document")
        .unwrap()
        .unwrap();
    let alice = PrincipalPolicyContext {
        subjects: vec!["alice".into()],
        scopes: Vec::new(),
    };
    let bob = PrincipalPolicyContext {
        subjects: vec!["bob".into()],
        scopes: Vec::new(),
    };
    let alice_object = object(namespace, "a", "alpha", "alice", "open");
    assert!(loaded.allows(&alice, &alice_object, ObjectSecurityOperation::Read));
    assert!(loaded.allows(&alice, &alice_object, ObjectSecurityOperation::Update));
    assert!(!loaded.allows(&bob, &alice_object, ObjectSecurityOperation::Update));
    assert_eq!(db.object_query_cursor_key().unwrap().len(), 32);
    assert_eq!(
        db.object_query_cursor_key().unwrap(),
        db.object_query_cursor_key().unwrap()
    );
}

#[test]
fn sqlite_object_security_conformance() {
    let db = RuntimeDb::Sqlite(Arc::new(SekaiDb::new(":memory:").unwrap()));
    exercise(db, "object-security-sqlite");
}

#[test]
fn sqlite_activation_requires_every_instantiated_kind() {
    let db = RuntimeDb::Sqlite(Arc::new(SekaiDb::new(":memory:").unwrap()));
    db.create_object(&object("incomplete", "doc", "doc", "alice", "open"))
        .unwrap();
    let mut other = object("incomplete", "other", "other", "alice", "open");
    other.kind = "other".into();
    db.create_object(&other).unwrap();
    let revision = db
        .put_object_security_policy(
            &policy(
                "incomplete",
                "document",
                vec![ObjectSecurityPredicate::AllowAll],
            ),
            "root",
            "put",
            1,
        )
        .unwrap();
    assert!(
        db.activate_object_security_policies(
            "incomplete",
            &BTreeMap::from([("document".into(), revision.revision_digest)]),
            "root",
            "activate",
            2,
        )
        .unwrap_err()
        .contains("activation_incomplete")
    );
}

#[test]
fn sqlite_unactivated_namespace_keeps_broad_unfiltered_listing() {
    let db = RuntimeDb::Sqlite(Arc::new(SekaiDb::new(":memory:").unwrap()));
    db.create_object(&object(
        "activated",
        "activated-doc",
        "activated",
        "alice",
        "open",
    ))
    .unwrap();
    db.create_object(&object("legacy", "legacy-doc", "legacy", "alice", "open"))
        .unwrap();
    let revision = db
        .put_object_security_policy(
            &policy(
                "activated",
                "document",
                vec![ObjectSecurityPredicate::AllowAll],
            ),
            "root",
            "put-activated",
            1,
        )
        .unwrap();
    db.activate_object_security_policies(
        "activated",
        &BTreeMap::from([("document".into(), revision.revision_digest)]),
        "root",
        "activate",
        2,
    )
    .unwrap();

    let (rows, total) = db
        .list_objects_with_total_for_policy_context(
            &ListFilter {
                limit: 100,
                ..Default::default()
            },
            &["alice"],
            &[],
            &PrincipalPolicyContext {
                subjects: vec!["alice".into()],
                scopes: vec![],
            },
        )
        .unwrap();
    assert_eq!(total, 2);
    assert!(
        rows.iter()
            .any(|row| row.id == object_id("legacy", "legacy-doc"))
    );
}

#[test]
fn sqlite_policy_lists_exclude_reserved_kinds() {
    let db = RuntimeDb::Sqlite(Arc::new(SekaiDb::new(":memory:").unwrap()));
    db.create_object(&object("ns", "doc", "doc", "alice", "open"))
        .unwrap();
    let mut reserved = object("ns", "cap", "cap", "alice", "open");
    reserved.kind = KIND_CAPABILITY.into();
    db.create_object(&reserved).unwrap();
    let (rows, total) = db
        .list_objects_with_total_for_policy_context(
            &ListFilter {
                namespace: Some("ns".into()),
                limit: 100,
                ..Default::default()
            },
            &["alice"],
            &[KIND_CAPABILITY],
            &PrincipalPolicyContext::default(),
        )
        .unwrap();
    assert_eq!(total, 1);
    assert_eq!(
        rows.iter().map(|row| row.id.clone()).collect::<Vec<_>>(),
        vec![object_id("ns", "doc")]
    );
}

#[test]
fn sqlite_rejects_nul_object_properties() {
    let db = RuntimeDb::Sqlite(Arc::new(SekaiDb::new(":memory:").unwrap()));
    let mut poisoned = object("ns", "poison", "poison", "alice", "open");
    poisoned.properties.insert("owner".into(), "alice\0".into());
    assert!(db.create_object(&poisoned).unwrap_err().contains("NUL"));

    let mut stored = object("ns", "ok", "ok", "alice", "open");
    db.create_object(&stored).unwrap();
    stored.updated = 2;
    stored.properties.insert("owner".into(), "alice\0".into());
    assert!(db.update_object(&stored).unwrap_err().contains("NUL"));
}

#[test]
fn sqlite_activation_audit_stores_mapping_digest() {
    let db = RuntimeDb::Sqlite(Arc::new(SekaiDb::new(":memory:").unwrap()));
    db.create_object(&object("audit", "doc", "doc", "alice", "open"))
        .unwrap();
    let revision = db
        .put_object_security_policy(
            &policy("audit", "document", vec![ObjectSecurityPredicate::AllowAll]),
            "root",
            "put-audit",
            1,
        )
        .unwrap();
    let activation = db
        .activate_object_security_policies(
            "audit",
            &BTreeMap::from([("document".into(), revision.revision_digest)]),
            "root",
            "activate-audit",
            2,
        )
        .unwrap();
    let digest: String = db
        .conn()
        .query_row(
            "SELECT revision_digest FROM sekai_object_security_audit
             WHERE action='activate' AND namespace=?1",
            ["audit"],
            |row| row.get(0),
        )
        .unwrap();
    assert_eq!(digest, activation.activation_id);
}

#[test]
#[ignore = "requires SEKAI_TEST_POSTGRES_URL for an isolated TLS PostgreSQL database"]
fn postgres_object_security_conformance() {
    let url = std::env::var("SEKAI_TEST_POSTGRES_URL")
        .expect("SEKAI_TEST_POSTGRES_URL must identify an isolated PostgreSQL database");
    let postgres = Arc::new(PostgresDb::connect(&url, 4).unwrap());
    let db = RuntimeDb::Postgres(postgres.clone());
    exercise(
        db,
        &format!("object-security-{}", uuid::Uuid::new_v4().simple()),
    );

    let namespace = format!("object-security-put-race-{}", uuid::Uuid::new_v4().simple());
    let policy = Arc::new(policy(
        &namespace,
        "document",
        vec![ObjectSecurityPredicate::AllowAll],
    ));
    let barrier = Arc::new(Barrier::new(2));
    let results = (0..2)
        .map(|index| {
            let postgres = postgres.clone();
            let policy = policy.clone();
            let barrier = barrier.clone();
            std::thread::spawn(move || {
                barrier.wait();
                postgres.put_object_security_policy(
                    &policy,
                    "root",
                    &format!("concurrent-put-{index}"),
                    42,
                )
            })
        })
        .map(|handle| handle.join().unwrap().unwrap())
        .collect::<Vec<_>>();
    assert_eq!(results[0], results[1]);
}
