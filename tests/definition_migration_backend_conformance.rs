use std::collections::{BTreeMap, HashMap};
use std::sync::Arc;

use sekai_chisei::db::postgres::PostgresDb;
use sekai_chisei::db::runtime_db::RuntimeDb;
use sekai_chisei::db::sekai::SekaiDb;
use sekai_chisei::domain::Object;
use sekai_chisei::sekai::definition_branch::{
    ApplyDefinitionBranchEdit, CreateDefinitionBranch, DefinitionMemberInput,
    DefinitionRevisionMember, DefinitionWriteResult, prepare_revision,
};
use sekai_chisei::sekai::definition_migration::{
    ExecuteFactMigration, MODE_DRY_RUN, MODE_EXECUTE, MODE_ROLLBACK, STATUS_BLOCKED,
    STATUS_COMMITTED, STATUS_DRY_RUN_COMPLETE, STATUS_ROLLED_BACK,
};
use sekai_chisei::sekai::definition_proposal::{
    ApproveDefinitionProposal, CreateDefinitionProposal, MergeDefinitionProposal,
};
use sekai_chisei::sekai::object_security::{
    OBJECT_SECURITY_POLICY_VERSION, ObjectSecurityOperation, ObjectSecurityPolicy,
    ObjectSecurityPredicate, ObjectSecurityRule, PrincipalPolicyContext, PropertyGrant,
    PropertyGrantAccess,
};

fn ctx(actor: &str) -> PrincipalPolicyContext {
    PrincipalPolicyContext {
        subjects: vec![actor.into()],
        scopes: vec![],
    }
}

fn member(namespace: &str, json: &str) -> DefinitionMemberInput {
    let mut input = DefinitionMemberInput {
        member_kind: "object_type".into(),
        member_id: "Ticket".into(),
        definition_json: json.into(),
        member_digest: String::new(),
    };
    input.member_digest = input.prepare(namespace).unwrap().member_digest;
    input
}

fn object(namespace: &str, id: &str, title: &str, secret: Option<&str>) -> Object {
    let mut properties = HashMap::from([("title".into(), title.into())]);
    if let Some(secret) = secret {
        properties.insert("secret".into(), secret.into());
    }
    Object {
        id: format!("{namespace}:{id}"),
        kind: "Ticket".into(),
        name: id.into(),
        namespace: namespace.into(),
        external_id: format!("{namespace}:{id}"),
        properties,
        created: 1,
        updated: 1,
    }
}

fn publish_breaking(db: &RuntimeDb, namespace: &str) -> (String, String) {
    let parent_member = member(
        namespace,
        r#"{"name":"Ticket","properties":["title","secret"]}"#,
    );
    let prepared = parent_member.prepare(namespace).unwrap();
    let revision = prepare_revision(
        namespace,
        "",
        [DefinitionRevisionMember {
            member_kind: prepared.member_kind.clone(),
            member_id: prepared.member_id.clone(),
            member_digest: prepared.member_digest.clone(),
        }],
        true,
        "root",
        1,
    )
    .unwrap();
    db.seed_published_definition_revision(&revision, &[prepared])
        .unwrap();
    let parent = revision.revision_digest.clone();
    db.create_definition_branch(
        &CreateDefinitionBranch {
            namespace: namespace.into(),
            branch_id: "migrate".into(),
            parent_revision_digest: parent.clone(),
            idempotency_key: "create".into(),
        },
        "author",
        2,
    )
    .unwrap();
    let DefinitionWriteResult::ApplyEdit { result } = db
        .apply_definition_branch_edit(
            &ApplyDefinitionBranchEdit {
                namespace: namespace.into(),
                branch_id: "migrate".into(),
                expected_head_digest: parent.clone(),
                upserts: vec![member(
                    namespace,
                    r#"{"name":"Ticket","properties":["title"]}"#,
                )],
                removals: Vec::new(),
                idempotency_key: "edit".into(),
            },
            "author",
            3,
        )
        .unwrap()
    else {
        panic!("expected edit");
    };
    let candidate = result.revision.revision_digest.clone();
    db.create_definition_proposal(
        &CreateDefinitionProposal {
            namespace: namespace.into(),
            branch_id: "migrate".into(),
            proposal_id: "mig".into(),
            base_digest: parent.clone(),
            candidate_digest: candidate.clone(),
            eval_plan_digests: Vec::new(),
            named_foreign_digests: Vec::new(),
            idempotency_key: "propose".into(),
        },
        "author",
        4,
    )
    .unwrap();
    db.approve_definition_proposal(
        &ApproveDefinitionProposal {
            namespace: namespace.into(),
            proposal_id: "mig".into(),
            idempotency_key: "approve".into(),
        },
        "author",
        5,
    )
    .unwrap();
    db.merge_definition_proposal(
        &MergeDefinitionProposal {
            namespace: namespace.into(),
            proposal_id: "mig".into(),
            expected_published_digest: parent.clone(),
            idempotency_key: "merge".into(),
        },
        "author",
        6,
    )
    .unwrap();
    (parent, candidate)
}

fn exercise(db: RuntimeDb, namespace: &str) {
    let (from, to) = publish_breaking(&db, namespace);
    db.create_object(&object(namespace, "open", "hello", Some("classified")))
        .unwrap();
    db.create_object(&object(namespace, "done", "kept", Some("x")))
        .unwrap();

    let dry = ExecuteFactMigration {
        namespace: namespace.into(),
        migration_id: "m1".into(),
        from_revision_digest: from.clone(),
        to_revision_digest: to.clone(),
        mode: MODE_DRY_RUN.into(),
        idempotency_key: "dry".into(),
    };
    let planned = db
        .execute_definition_fact_migration(&dry, "author", &ctx("author"), 7)
        .unwrap();
    assert_eq!(
        db.execute_definition_fact_migration(&dry, "author", &ctx("author"), 8)
            .unwrap(),
        planned
    );
    assert_eq!(planned.status, STATUS_DRY_RUN_COMPLETE);
    assert_eq!(planned.affected_count, 2);
    assert_eq!(planned.migrated_count, 0);
    assert_eq!(planned.compatibility_class, "breaking");
    let stored = db
        .get_object(&format!("{namespace}:open"))
        .unwrap()
        .unwrap();
    assert_eq!(stored.properties.get("secret").unwrap(), "classified");

    let execute = ExecuteFactMigration {
        namespace: namespace.into(),
        migration_id: "m1".into(),
        from_revision_digest: from.clone(),
        to_revision_digest: to.clone(),
        mode: MODE_EXECUTE.into(),
        idempotency_key: "run".into(),
    };
    let committed = db
        .execute_definition_fact_migration(&execute, "author", &ctx("author"), 9)
        .unwrap();
    assert_eq!(committed.status, STATUS_COMMITTED);
    assert_eq!(committed.migrated_count, 2);
    assert_eq!(
        db.execute_definition_fact_migration(&execute, "author", &ctx("author"), 10)
            .unwrap(),
        committed
    );
    assert!(
        db.count_definition_fact_migration_audit(namespace, "m1")
            .unwrap()
            >= 1
    );
    assert!(
        !db.list_object_changes(&format!("{namespace}:open"), 16, 0)
            .unwrap()
            .is_empty()
    );
    let migrated = db
        .get_object(&format!("{namespace}:open"))
        .unwrap()
        .unwrap();
    assert!(!migrated.properties.contains_key("secret"));
    assert_eq!(migrated.properties.get("title").unwrap(), "hello");
    assert_eq!(
        db.get_definition_fact_migration(namespace, "m1")
            .unwrap()
            .unwrap()
            .status,
        STATUS_COMMITTED
    );

    let rollback = ExecuteFactMigration {
        namespace: namespace.into(),
        migration_id: "m1".into(),
        from_revision_digest: from.clone(),
        to_revision_digest: to.clone(),
        mode: MODE_ROLLBACK.into(),
        idempotency_key: "undo".into(),
    };
    let rolled = db
        .execute_definition_fact_migration(&rollback, "author", &ctx("author"), 11)
        .unwrap();
    assert_eq!(rolled.status, STATUS_ROLLED_BACK);
    let restored = db
        .get_object(&format!("{namespace}:open"))
        .unwrap()
        .unwrap();
    assert_eq!(restored.properties.get("secret").unwrap(), "classified");

    let missing = ExecuteFactMigration {
        namespace: namespace.into(),
        migration_id: "blocked".into(),
        from_revision_digest: from,
        to_revision_digest: to,
        mode: MODE_EXECUTE.into(),
        idempotency_key: "block".into(),
    };
    db.create_object(&object(namespace, "empty", "only-title", None))
        .unwrap();
    let blocked = db.execute_definition_fact_migration(&missing, "author", &ctx("author"), 12);
    // empty object still has title; execute after rollback re-migrates remaining
    // objects bound to from. The empty object is migratable. Use a required-property
    // case via a second namespace in the unit tests; here assert replay/unknown
    // still fail closed.
    let _ = blocked;
    let mut unknown = ExecuteFactMigration {
        namespace: namespace.into(),
        migration_id: "nope".into(),
        from_revision_digest: format!("sha256:{}", "a".repeat(64)),
        to_revision_digest: format!("sha256:{}", "b".repeat(64)),
        mode: MODE_DRY_RUN.into(),
        idempotency_key: "missing".into(),
    };
    assert!(
        db.execute_definition_fact_migration(&unknown, "author", &ctx("author"), 13)
            .unwrap_err()
            .contains("definition_revision_not_found")
    );
    unknown.mode = "explode".into();
    unknown.idempotency_key = "bad-mode".into();
    assert!(
        db.execute_definition_fact_migration(&unknown, "author", &ctx("author"), 14)
            .unwrap_err()
            .contains("fact_migration_unsupported_mode")
    );
}

fn sqlite_db() -> RuntimeDb {
    RuntimeDb::Sqlite(Arc::new(SekaiDb::new(":memory:").unwrap()))
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
fn sqlite_definition_fact_migration_conformance() {
    exercise(sqlite_db(), "fact-mig-sqlite");
}

#[test]
fn sqlite_blocked_transform_does_not_mutate() {
    let db = sqlite_db();
    let namespace = "blocked-ns";
    let parent_member = member(namespace, r#"{"name":"Ticket","properties":["title"]}"#);
    let prepared = parent_member.prepare(namespace).unwrap();
    let revision = prepare_revision(
        namespace,
        "",
        [DefinitionRevisionMember {
            member_kind: prepared.member_kind.clone(),
            member_id: prepared.member_id.clone(),
            member_digest: prepared.member_digest.clone(),
        }],
        true,
        "root",
        1,
    )
    .unwrap();
    db.seed_published_definition_revision(&revision, &[prepared])
        .unwrap();
    let parent = revision.revision_digest;
    db.create_definition_branch(
        &CreateDefinitionBranch {
            namespace: namespace.into(),
            branch_id: "req".into(),
            parent_revision_digest: parent.clone(),
            idempotency_key: "c".into(),
        },
        "author",
        2,
    )
    .unwrap();
    let DefinitionWriteResult::ApplyEdit { result } = db
        .apply_definition_branch_edit(
            &ApplyDefinitionBranchEdit {
                namespace: namespace.into(),
                branch_id: "req".into(),
                expected_head_digest: parent.clone(),
                upserts: vec![member(
                    namespace,
                    r#"{"name":"Ticket","properties":["title","severity"],"required":["severity"]}"#,
                )],
                removals: Vec::new(),
                idempotency_key: "e".into(),
            },
            "author",
            3,
        )
        .unwrap()
    else {
        panic!("expected edit");
    };
    let candidate = result.revision.revision_digest;
    db.create_definition_proposal(
        &CreateDefinitionProposal {
            namespace: namespace.into(),
            branch_id: "req".into(),
            proposal_id: "p".into(),
            base_digest: parent.clone(),
            candidate_digest: candidate.clone(),
            eval_plan_digests: Vec::new(),
            named_foreign_digests: Vec::new(),
            idempotency_key: "pr".into(),
        },
        "author",
        4,
    )
    .unwrap();
    db.approve_definition_proposal(
        &ApproveDefinitionProposal {
            namespace: namespace.into(),
            proposal_id: "p".into(),
            idempotency_key: "ap".into(),
        },
        "author",
        5,
    )
    .unwrap();
    db.merge_definition_proposal(
        &MergeDefinitionProposal {
            namespace: namespace.into(),
            proposal_id: "p".into(),
            expected_published_digest: parent.clone(),
            idempotency_key: "mg".into(),
        },
        "author",
        6,
    )
    .unwrap();
    db.create_object(&object(namespace, "t", "hello", None))
        .unwrap();
    let result = db
        .execute_definition_fact_migration(
            &ExecuteFactMigration {
                namespace: namespace.into(),
                migration_id: "need-sev".into(),
                from_revision_digest: parent,
                to_revision_digest: candidate,
                mode: MODE_EXECUTE.into(),
                idempotency_key: "ex".into(),
            },
            "author",
            &ctx("author"),
            7,
        )
        .unwrap();
    assert_eq!(result.status, STATUS_BLOCKED);
    assert_eq!(result.blocked_count, 1);
    assert_eq!(result.blocked[0].reason_code, "missing_required");
    let stored = db.get_object(&format!("{namespace}:t")).unwrap().unwrap();
    assert_eq!(stored.properties.get("title").unwrap(), "hello");
    assert!(!stored.properties.contains_key("severity"));
}

#[test]
fn sqlite_rollback_requires_stored_revision_identity() {
    exercise_rollback_mismatch(sqlite_db(), "fact-mig-mismatch");
}

#[test]
fn sqlite_fact_migration_omits_hidden_and_preserves_ungranted_properties() {
    exercise_object_security_and_property_grants(sqlite_db(), "fact-mig-auth");
}

#[test]
#[ignore = "requires SEKAI_TEST_POSTGRES_URL for an isolated TLS PostgreSQL database"]
fn postgres_definition_fact_migration_conformance() {
    let prefix = format!("pg-fact-mig-{}", uuid::Uuid::new_v4().simple());
    let db = RuntimeDb::Postgres(Arc::new(postgres()));
    exercise(db.clone(), &prefix);
    exercise_rollback_mismatch(db.clone(), &format!("{prefix}-mismatch"));
    exercise_object_security_and_property_grants(db.clone(), &format!("{prefix}-auth"));
    exercise_rollback_denied_when_snapshot_hidden(db.clone(), &format!("{prefix}-hidden-rb"));
    exercise_rollback_denied_when_ungranted_property_differs(db, &format!("{prefix}-grant-rb"));
}

fn exercise_rollback_mismatch(db: RuntimeDb, namespace: &str) {
    let (from, to) = publish_breaking(&db, namespace);
    db.create_object(&object(namespace, "open", "hello", Some("classified")))
        .unwrap();
    let execute = ExecuteFactMigration {
        namespace: namespace.into(),
        migration_id: "m-mismatch".into(),
        from_revision_digest: from.clone(),
        to_revision_digest: to.clone(),
        mode: MODE_EXECUTE.into(),
        idempotency_key: "run".into(),
    };
    let committed = db
        .execute_definition_fact_migration(&execute, "author", &ctx("author"), 9)
        .unwrap();
    assert_eq!(committed.status, STATUS_COMMITTED);
    let mut rollback = ExecuteFactMigration {
        namespace: namespace.into(),
        migration_id: "m-mismatch".into(),
        from_revision_digest: format!("sha256:{}", "c".repeat(64)),
        to_revision_digest: to,
        mode: MODE_ROLLBACK.into(),
        idempotency_key: "undo-wrong".into(),
    };
    let error = db
        .execute_definition_fact_migration(&rollback, "author", &ctx("author"), 10)
        .unwrap_err();
    assert!(
        error.contains("fact_migration_revision_mismatch"),
        "{error}"
    );
    let migrated = db
        .get_object(&format!("{namespace}:open"))
        .unwrap()
        .unwrap();
    assert!(!migrated.properties.contains_key("secret"));
    rollback.from_revision_digest = from.clone();
    rollback.idempotency_key = "undo-right".into();
    let rolled = db
        .execute_definition_fact_migration(&rollback, "author", &ctx("author"), 11)
        .unwrap();
    assert_eq!(rolled.status, STATUS_ROLLED_BACK);
    let rerun = ExecuteFactMigration {
        namespace: namespace.into(),
        migration_id: "m-mismatch".into(),
        from_revision_digest: from,
        to_revision_digest: rollback.to_revision_digest.clone(),
        mode: MODE_EXECUTE.into(),
        idempotency_key: "run-again".into(),
    };
    let committed_again = db
        .execute_definition_fact_migration(&rerun, "author", &ctx("author"), 12)
        .unwrap();
    assert_eq!(committed_again.status, STATUS_COMMITTED);
    assert!(
        db.count_definition_fact_migration_audit(namespace, "m-mismatch")
            .unwrap()
            >= 3
    );
}

fn exercise_object_security_and_property_grants(db: RuntimeDb, namespace: &str) {
    let (from, to) = publish_breaking(&db, namespace);
    let mut visible = object(namespace, "mine", "hello", Some("classified"));
    visible.properties.insert("owner".into(), "author".into());
    let mut hidden = object(namespace, "theirs", "hidden", Some("keep-me"));
    hidden.properties.insert("owner".into(), "bob".into());
    db.create_object(&visible).unwrap();
    db.create_object(&hidden).unwrap();

    let policy = ObjectSecurityPolicy {
        contract_version: OBJECT_SECURITY_POLICY_VERSION.into(),
        namespace: namespace.into(),
        kind: "Ticket".into(),
        rules: vec![ObjectSecurityRule {
            operation: ObjectSecurityOperation::Read,
            predicates: vec![ObjectSecurityPredicate::SubjectEqualsProperty {
                property: "owner".into(),
            }],
        }],
        property_grants: Some(vec![
            PropertyGrant {
                property: "title".into(),
                access: PropertyGrantAccess::Read,
            },
            PropertyGrant {
                property: "title".into(),
                access: PropertyGrantAccess::Write,
            },
            PropertyGrant {
                property: "owner".into(),
                access: PropertyGrantAccess::Read,
            },
        ]),
    };
    let revision = db
        .put_object_security_policy(&policy, "root", "put-mig-grants", 1)
        .unwrap();
    db.activate_object_security_policies(
        namespace,
        &BTreeMap::from([("Ticket".into(), revision.revision_digest)]),
        "root",
        "activate-mig-grants",
        2,
    )
    .unwrap();

    let committed = db
        .execute_definition_fact_migration(
            &ExecuteFactMigration {
                namespace: namespace.into(),
                migration_id: "m-auth".into(),
                from_revision_digest: from,
                to_revision_digest: to,
                mode: MODE_EXECUTE.into(),
                idempotency_key: "run-auth".into(),
            },
            "author",
            &ctx("author"),
            9,
        )
        .unwrap();
    assert_eq!(committed.status, STATUS_COMMITTED);
    assert_eq!(committed.migrated_count, 1);
    assert_eq!(committed.objects.len(), 1);
    assert_eq!(committed.objects[0].object_id, format!("{namespace}:mine"));

    let mine = db
        .get_object(&format!("{namespace}:mine"))
        .unwrap()
        .unwrap();
    assert_eq!(mine.properties.get("title").unwrap(), "hello");
    assert_eq!(mine.properties.get("secret").unwrap(), "classified");
    assert_eq!(mine.properties.get("owner").unwrap(), "author");
    assert!(
        !committed.objects[0]
            .stripped_properties
            .iter()
            .any(|property| property == "secret")
    );
    let theirs = db
        .get_object(&format!("{namespace}:theirs"))
        .unwrap()
        .unwrap();
    assert_eq!(theirs.properties.get("secret").unwrap(), "keep-me");
    assert!(
        db.count_definition_fact_migration_audit(namespace, "m-auth")
            .unwrap()
            >= 1
    );
}

#[test]
fn sqlite_rollback_fails_closed_when_a_snapshot_is_hidden() {
    exercise_rollback_denied_when_snapshot_hidden(sqlite_db(), "fact-mig-hidden-rb");
}

fn exercise_rollback_denied_when_snapshot_hidden(db: RuntimeDb, namespace: &str) {
    let (from, to) = publish_breaking(&db, namespace);
    let mut visible = object(namespace, "mine", "hello", Some("classified"));
    visible.properties.insert("owner".into(), "author".into());
    let mut later_hidden = object(namespace, "later", "other", Some("keep-me"));
    later_hidden.properties.insert("owner".into(), "bob".into());
    db.create_object(&visible).unwrap();
    db.create_object(&later_hidden).unwrap();
    let committed = db
        .execute_definition_fact_migration(
            &ExecuteFactMigration {
                namespace: namespace.into(),
                migration_id: "m-hidden-rb".into(),
                from_revision_digest: from.clone(),
                to_revision_digest: to.clone(),
                mode: MODE_EXECUTE.into(),
                idempotency_key: "run".into(),
            },
            "author",
            &ctx("author"),
            9,
        )
        .unwrap();
    assert_eq!(committed.status, STATUS_COMMITTED);
    assert_eq!(committed.migrated_count, 2);

    let policy = ObjectSecurityPolicy {
        contract_version: OBJECT_SECURITY_POLICY_VERSION.into(),
        namespace: namespace.into(),
        kind: "Ticket".into(),
        rules: vec![ObjectSecurityRule {
            operation: ObjectSecurityOperation::Read,
            predicates: vec![ObjectSecurityPredicate::SubjectEqualsProperty {
                property: "owner".into(),
            }],
        }],
        property_grants: None,
    };
    let revision = db
        .put_object_security_policy(&policy, "root", "put-hidden-rb", 10)
        .unwrap();
    db.activate_object_security_policies(
        namespace,
        &BTreeMap::from([("Ticket".into(), revision.revision_digest)]),
        "root",
        "activate-hidden-rb",
        11,
    )
    .unwrap();

    let error = db
        .execute_definition_fact_migration(
            &ExecuteFactMigration {
                namespace: namespace.into(),
                migration_id: "m-hidden-rb".into(),
                from_revision_digest: from,
                to_revision_digest: to,
                mode: MODE_ROLLBACK.into(),
                idempotency_key: "undo".into(),
            },
            "author",
            &ctx("author"),
            12,
        )
        .unwrap_err();
    assert!(error.contains("fact_migration_rollback_denied"), "{error}");
    let stored = db
        .get_definition_fact_migration(namespace, "m-hidden-rb")
        .unwrap()
        .unwrap();
    assert_eq!(stored.status, STATUS_COMMITTED);
    let mine = db
        .get_object(&format!("{namespace}:mine"))
        .unwrap()
        .unwrap();
    assert!(!mine.properties.contains_key("secret"));
}

#[test]
fn sqlite_rollback_fails_closed_when_ungranted_snapshot_differs() {
    exercise_rollback_denied_when_ungranted_property_differs(sqlite_db(), "fact-mig-grant-rb");
}

fn exercise_rollback_denied_when_ungranted_property_differs(db: RuntimeDb, namespace: &str) {
    let (from, to) = publish_breaking(&db, namespace);
    db.create_object(&object(namespace, "open", "hello", Some("classified")))
        .unwrap();
    let writable = ObjectSecurityPolicy {
        contract_version: OBJECT_SECURITY_POLICY_VERSION.into(),
        namespace: namespace.into(),
        kind: "Ticket".into(),
        rules: vec![ObjectSecurityRule {
            operation: ObjectSecurityOperation::Read,
            predicates: vec![ObjectSecurityPredicate::AllowAll],
        }],
        property_grants: Some(vec![
            PropertyGrant {
                property: "title".into(),
                access: PropertyGrantAccess::Read,
            },
            PropertyGrant {
                property: "title".into(),
                access: PropertyGrantAccess::Write,
            },
            PropertyGrant {
                property: "secret".into(),
                access: PropertyGrantAccess::Read,
            },
            PropertyGrant {
                property: "secret".into(),
                access: PropertyGrantAccess::Write,
            },
        ]),
    };
    let writable_revision = db
        .put_object_security_policy(&writable, "root", "put-writable", 1)
        .unwrap();
    db.activate_object_security_policies(
        namespace,
        &BTreeMap::from([("Ticket".into(), writable_revision.revision_digest)]),
        "root",
        "activate-writable",
        2,
    )
    .unwrap();
    let committed = db
        .execute_definition_fact_migration(
            &ExecuteFactMigration {
                namespace: namespace.into(),
                migration_id: "m-grant-rb".into(),
                from_revision_digest: from.clone(),
                to_revision_digest: to.clone(),
                mode: MODE_EXECUTE.into(),
                idempotency_key: "run".into(),
            },
            "author",
            &ctx("author"),
            9,
        )
        .unwrap();
    assert_eq!(committed.status, STATUS_COMMITTED);
    assert!(
        committed.objects[0]
            .stripped_properties
            .iter()
            .any(|property| property == "secret")
    );

    let readonly_secret = ObjectSecurityPolicy {
        contract_version: OBJECT_SECURITY_POLICY_VERSION.into(),
        namespace: namespace.into(),
        kind: "Ticket".into(),
        rules: vec![ObjectSecurityRule {
            operation: ObjectSecurityOperation::Read,
            predicates: vec![ObjectSecurityPredicate::AllowAll],
        }],
        property_grants: Some(vec![
            PropertyGrant {
                property: "title".into(),
                access: PropertyGrantAccess::Read,
            },
            PropertyGrant {
                property: "title".into(),
                access: PropertyGrantAccess::Write,
            },
            PropertyGrant {
                property: "secret".into(),
                access: PropertyGrantAccess::Read,
            },
        ]),
    };
    let readonly_revision = db
        .put_object_security_policy(&readonly_secret, "root", "put-readonly", 10)
        .unwrap();
    db.activate_object_security_policies(
        namespace,
        &BTreeMap::from([("Ticket".into(), readonly_revision.revision_digest)]),
        "root",
        "activate-readonly",
        11,
    )
    .unwrap();
    let error = db
        .execute_definition_fact_migration(
            &ExecuteFactMigration {
                namespace: namespace.into(),
                migration_id: "m-grant-rb".into(),
                from_revision_digest: from,
                to_revision_digest: to,
                mode: MODE_ROLLBACK.into(),
                idempotency_key: "undo".into(),
            },
            "author",
            &ctx("author"),
            12,
        )
        .unwrap_err();
    assert!(error.contains("fact_migration_rollback_denied"), "{error}");
    let stored = db
        .get_object(&format!("{namespace}:open"))
        .unwrap()
        .unwrap();
    assert!(!stored.properties.contains_key("secret"));
}
