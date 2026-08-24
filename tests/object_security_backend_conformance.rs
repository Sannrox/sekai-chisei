use sekai_chisei::db::object_security::ObjectSecurityBackend;
use sekai_chisei::db::runtime_db::RuntimeDb;
use sekai_chisei::db::{postgres::PostgresDb, sekai::SekaiDb};
use sekai_chisei::domain::{ListFilter, Object, PropertyFilter};
use sekai_chisei::sekai::object_security::{
    ActivateObjectSecurityProfile, ConditionOperator, ObjectSecurityPolicyBinding,
    ObjectSecurityPolicyInput, ObjectSecurityRule, ObjectSecurityWriteResult, OperandSource,
    PolicyCondition, PolicyOperand, PrincipalSecurityContext, RevokeObjectSecurityPolicy,
};
use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::sync::Arc;

fn policy(
    namespace: &str,
    kind: &str,
    revision: &str,
    idempotency_key: &str,
) -> ObjectSecurityPolicyInput {
    ObjectSecurityPolicyInput {
        namespace: namespace.into(),
        object_kind: kind.into(),
        revision: revision.into(),
        rules: vec![ObjectSecurityRule {
            rule_id: "compatibility-allow".into(),
            conditions: Vec::new(),
        }],
        policy_digest: String::new(),
        idempotency_key: idempotency_key.into(),
    }
}

fn created_policy_digest(result: &ObjectSecurityWriteResult) -> &str {
    let ObjectSecurityWriteResult::CreatePolicy { record } = result else {
        panic!("expected created policy");
    };
    &record.policy.policy_digest
}

fn exercise_backend(db: &dyn ObjectSecurityBackend, namespace: &str) {
    let cursor_key = db.object_query_cursor_key().unwrap();
    assert_ne!(cursor_key, [0; 32]);
    assert_eq!(cursor_key, db.object_query_cursor_key().unwrap());

    let artifact = policy(namespace, "artifact", "1", "create-artifact");
    let artifact_created = db
        .create_object_security_policy(&artifact, "root", 1)
        .unwrap();
    assert_eq!(
        artifact_created,
        db.create_object_security_policy(&artifact, "root", 2)
            .unwrap()
    );
    let artifact_digest = created_policy_digest(&artifact_created).to_string();
    let mut reused_input = artifact.clone();
    reused_input.idempotency_key = "create-artifact-reuse".into();
    let reused = db
        .create_object_security_policy(&reused_input, "other", 99)
        .unwrap();
    assert_eq!(created_policy_digest(&reused), artifact_digest);
    let ObjectSecurityWriteResult::CreatePolicy {
        record: reused_record,
    } = reused
    else {
        panic!("expected reused policy");
    };
    let ObjectSecurityWriteResult::CreatePolicy {
        record: original_record,
    } = &artifact_created
    else {
        panic!("expected created policy");
    };
    assert_eq!(
        reused_record.policy.created_by,
        original_record.policy.created_by
    );
    assert_eq!(
        reused_record.policy.created_at_ms,
        original_record.policy.created_at_ms
    );

    let operation = policy(namespace, "operation", "1", "create-operation");
    let operation_created = db
        .create_object_security_policy(&operation, "root", 3)
        .unwrap();
    let operation_digest = created_policy_digest(&operation_created).to_string();

    let mut conflicting = artifact.clone();
    conflicting.revision = "2".into();
    assert!(
        db.create_object_security_policy(&conflicting, "root", 4)
            .unwrap_err()
            .contains("object_security_idempotency_conflict")
    );

    let activate = ActivateObjectSecurityProfile {
        namespace: namespace.into(),
        expected_profile_digest: String::new(),
        bindings: vec![
            ObjectSecurityPolicyBinding {
                object_kind: "operation".into(),
                policy_digest: operation_digest,
            },
            ObjectSecurityPolicyBinding {
                object_kind: "artifact".into(),
                policy_digest: artifact_digest.clone(),
            },
        ],
        idempotency_key: "activate-1".into(),
    };
    let activated = db
        .activate_object_security_profile(
            &activate,
            &["artifact".into(), "operation".into()],
            "root",
            5,
        )
        .unwrap();
    assert_eq!(
        activated,
        db.activate_object_security_profile(
            &activate,
            &["operation".into(), "artifact".into()],
            "root",
            6,
        )
        .unwrap()
    );
    let ObjectSecurityWriteResult::ActivateProfile { profile } = activated else {
        panic!("expected activated profile");
    };
    assert_eq!(
        db.get_object_security_profile(namespace).unwrap().unwrap(),
        profile
    );
    assert!(db.object_security_kind_is_active("artifact").unwrap());
    assert!(
        db.active_object_security_policies_for_kind("artifact")
            .unwrap()
            .iter()
            .any(|record| record.policy.namespace == namespace
                && record.policy.policy_digest == artifact_digest)
    );
    assert_eq!(
        db.get_active_object_security_policy(namespace, "artifact")
            .unwrap()
            .unwrap()
            .policy
            .policy_digest,
        artifact_digest
    );

    let replacement_policy = policy(namespace, "artifact", "2", "create-artifact-2");
    let replacement_digest = created_policy_digest(
        &db.create_object_security_policy(&replacement_policy, "root", 7)
            .unwrap(),
    )
    .to_string();
    let replacement = ActivateObjectSecurityProfile {
        namespace: namespace.into(),
        expected_profile_digest: profile.profile_digest.clone(),
        bindings: vec![
            ObjectSecurityPolicyBinding {
                object_kind: "artifact".into(),
                policy_digest: replacement_digest.clone(),
            },
            profile.bindings[1].clone(),
        ],
        idempotency_key: "activate-2".into(),
    };
    let ObjectSecurityWriteResult::ActivateProfile {
        profile: replacement_profile,
    } = db
        .activate_object_security_profile(
            &replacement,
            &["artifact".into(), "operation".into()],
            "root",
            8,
        )
        .unwrap()
    else {
        panic!("expected replacement profile");
    };
    assert_ne!(replacement_profile.profile_digest, profile.profile_digest);

    let mut stale = replacement.clone();
    stale.idempotency_key = "activate-stale".into();
    assert!(
        db.activate_object_security_profile(
            &stale,
            &["artifact".into(), "operation".into()],
            "root",
            9,
        )
        .unwrap_err()
        .contains("stale_object_security_profile")
    );

    let revoke = RevokeObjectSecurityPolicy {
        namespace: namespace.into(),
        policy_digest: replacement_digest,
        reason: "operator emergency revocation".into(),
        idempotency_key: "revoke-1".into(),
    };
    let revoked = db
        .revoke_object_security_policy(&revoke, "root", 10)
        .unwrap();
    assert_eq!(
        revoked,
        db.revoke_object_security_policy(&revoke, "root", 11)
            .unwrap()
    );
    assert!(
        db.get_active_object_security_policy(namespace, "artifact")
            .unwrap()
            .unwrap()
            .revocation
            .is_some()
    );

    let incomplete = ActivateObjectSecurityProfile {
        namespace: namespace.into(),
        expected_profile_digest: replacement_profile.profile_digest,
        bindings: vec![ObjectSecurityPolicyBinding {
            object_kind: "artifact".into(),
            policy_digest: artifact_digest,
        }],
        idempotency_key: "activate-incomplete".into(),
    };
    assert!(
        db.activate_object_security_profile(
            &incomplete,
            &["artifact".into(), "operation".into()],
            "root",
            12,
        )
        .unwrap_err()
        .contains("every advertised object type")
    );
}

fn exercise_storage_authorized_query(db: &RuntimeDb, namespace: &str) {
    let owner_policy = ObjectSecurityPolicyInput {
        namespace: namespace.into(),
        object_kind: "artifact".into(),
        revision: "owner-1".into(),
        rules: vec![ObjectSecurityRule {
            rule_id: "owner".into(),
            conditions: vec![PolicyCondition {
                left: PolicyOperand {
                    source: OperandSource::ObjectProperty,
                    name: "owner".into(),
                    value: String::new(),
                },
                operator: ConditionOperator::Equals,
                right: PolicyOperand {
                    source: OperandSource::PrincipalAttribute,
                    name: "subject".into(),
                    value: String::new(),
                },
            }],
        }],
        policy_digest: String::new(),
        idempotency_key: "owner-policy".into(),
    };
    let digest = created_policy_digest(
        &db.create_object_security_policy(&owner_policy, "root", 20)
            .unwrap(),
    )
    .to_string();
    db.activate_object_security_profile(
        &ActivateObjectSecurityProfile {
            namespace: namespace.into(),
            expected_profile_digest: String::new(),
            bindings: vec![ObjectSecurityPolicyBinding {
                object_kind: "artifact".into(),
                policy_digest: digest,
            }],
            idempotency_key: "owner-profile".into(),
        },
        &["artifact".into()],
        "root",
        21,
    )
    .unwrap();
    for (suffix, owner) in [("alice", "alice"), ("bob", "bob")] {
        db.create_object_with_audit(
            &Object {
                id: format!("{namespace}-{suffix}"),
                kind: "artifact".into(),
                name: suffix.into(),
                namespace: namespace.into(),
                external_id: format!("{namespace}:{suffix}"),
                properties: HashMap::from([("owner".into(), owner.into())]),
                created: 22,
                updated: 22,
            },
            "root",
        )
        .unwrap();
    }
    let principal = PrincipalSecurityContext {
        attributes: BTreeMap::from([("subject".into(), "alice".into())]),
        entitlements: BTreeSet::new(),
    };
    let filter = ListFilter {
        namespace: Some(namespace.into()),
        kind: Some("artifact".into()),
        order_by: "name".into(),
        limit: 100,
        ..Default::default()
    };
    let (objects, total) = db
        .list_objects_with_object_security(
            &filter,
            &["alice"],
            &[],
            &principal,
            "query",
            &[],
            false,
        )
        .unwrap();
    assert_eq!(total, 1);
    assert_eq!(objects[0].properties["owner"], "alice");
    assert!(
        db.get_object_with_object_security(
            &format!("{namespace}-alice"),
            &["alice"],
            &principal,
            "read",
            &[],
            false,
        )
        .unwrap()
        .is_some()
    );
    assert!(
        db.get_object_with_object_security(
            &format!("{namespace}-bob"),
            &["alice"],
            &principal,
            "read",
            &[],
            false,
        )
        .unwrap()
        .is_none()
    );

    let denied_filter = ListFilter {
        property_filters: vec![PropertyFilter {
            key: "owner".into(),
            op: "eq".into(),
            value: "bob".into(),
        }],
        ..filter.clone()
    };
    let (objects, total) = db
        .list_objects_with_object_security(
            &denied_filter,
            &["alice"],
            &[],
            &principal,
            "query",
            &[],
            false,
        )
        .unwrap();
    assert!(objects.is_empty());
    assert_eq!(total, 0);

    for index in 0..101 {
        db.create_object_with_audit(
            &Object {
                id: format!("{namespace}-page-{index}"),
                kind: "artifact".into(),
                name: format!("page-{index:03}"),
                namespace: namespace.into(),
                external_id: format!("{namespace}:page-{index}"),
                properties: HashMap::from([("owner".into(), "alice".into())]),
                created: 23,
                updated: 23,
            },
            "root",
        )
        .unwrap();
    }
    let defaulted = ListFilter {
        limit: 0,
        offset: 0,
        ..filter.clone()
    };
    let (objects, total) = db
        .list_objects_with_object_security(
            &defaulted,
            &["alice"],
            &[],
            &principal,
            "query",
            &[],
            false,
        )
        .unwrap();
    assert_eq!(total, 102);
    assert_eq!(objects.len(), 100);
}

#[test]
fn sqlite_object_security_backend_conformance() {
    let db = SekaiDb::new(":memory:").unwrap();
    exercise_backend(&db, "sqlite-object-security");
    exercise_storage_authorized_query(
        &RuntimeDb::Sqlite(Arc::new(db)),
        "sqlite-object-security-query",
    );
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
fn postgres_object_security_backend_conformance() {
    let db = postgres();
    exercise_backend(
        &db,
        &format!("pg-object-security-{}", uuid::Uuid::new_v4().simple()),
    );
    exercise_storage_authorized_query(
        &RuntimeDb::Postgres(Arc::new(db)),
        &format!("pg-object-security-query-{}", uuid::Uuid::new_v4().simple()),
    );
}
