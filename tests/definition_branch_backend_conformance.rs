use std::sync::{Arc, Barrier};

use sekai_chisei::db::definition_branch::DefinitionBranchBackend;
use sekai_chisei::db::{postgres::PostgresDb, sekai::SekaiDb};
use sekai_chisei::sekai::definition_branch::{
    ApplyDefinitionBranchEdit, CreateDefinitionBranch, DefinitionMemberInput,
    DefinitionRevisionMember, DefinitionWriteResult, prepare_revision,
};

fn member(namespace: &str, member_id: &str, definition_json: &str) -> DefinitionMemberInput {
    let mut input = DefinitionMemberInput {
        member_kind: "object_type".into(),
        member_id: member_id.into(),
        definition_json: definition_json.into(),
        member_digest: String::new(),
    };
    input.member_digest = input.prepare(namespace).unwrap().member_digest;
    input
}

fn seed(db: &dyn DefinitionBranchBackend, namespace: &str) -> (String, CreateDefinitionBranch) {
    let input = member(namespace, "Ticket", r#"{"name":"Ticket"}"#);
    let prepared = input.prepare(namespace).unwrap();
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
    let request = CreateDefinitionBranch {
        namespace: namespace.into(),
        branch_id: "feature".into(),
        parent_revision_digest: revision.revision_digest.clone(),
        idempotency_key: "create-1".into(),
    };
    (revision.revision_digest, request)
}

fn exercise_backend(db: &dyn DefinitionBranchBackend, namespace: &str) {
    let (parent_digest, create) = seed(db, namespace);
    let first = db.create_definition_branch(&create, "author", 2).unwrap();
    assert_eq!(
        first,
        db.create_definition_branch(&create, "author", 3).unwrap()
    );
    let DefinitionWriteResult::CreateBranch { branch } = first else {
        panic!("expected branch creation");
    };
    assert_eq!(branch.base_revision_digest, parent_digest);
    assert_eq!(branch.head_revision_digest, parent_digest);

    let edit = ApplyDefinitionBranchEdit {
        namespace: namespace.into(),
        branch_id: branch.branch_id,
        expected_head_digest: parent_digest.clone(),
        upserts: vec![member(
            namespace,
            "Ticket",
            r#"{"name":"Ticket","properties":["title"]}"#,
        )],
        removals: Vec::new(),
        idempotency_key: "edit-1".into(),
    };
    let applied = db.apply_definition_branch_edit(&edit, "author", 4).unwrap();
    let mut reordered_replay = edit.clone();
    reordered_replay.upserts = vec![member(
        namespace,
        "Ticket",
        r#"{"properties":["title"],"name":"Ticket"}"#,
    )];
    assert_eq!(
        applied,
        db.apply_definition_branch_edit(&reordered_replay, "author", 5)
            .unwrap()
    );
    let DefinitionWriteResult::ApplyEdit { result } = applied else {
        panic!("expected branch edit");
    };
    assert_eq!(result.previous_head_digest, parent_digest);
    assert_eq!(result.revision.parent_revision_digest, parent_digest);
    assert!(!result.revision.published);
    assert_eq!(result.changed_member_digests.len(), 1);
    assert_eq!(
        db.get_definition_branch(namespace, "feature")
            .unwrap()
            .unwrap(),
        result.branch
    );

    let parent = db
        .get_definition_revision(namespace, &result.previous_head_digest)
        .unwrap()
        .unwrap();
    assert!(parent.published);
    assert_eq!(
        parent.members[0].member_digest,
        member(namespace, "Ticket", r#"{"name":"Ticket"}"#).member_digest
    );
    let ticket_digest = result.revision.members[0].member_digest.clone();
    let remove = ApplyDefinitionBranchEdit {
        namespace: namespace.into(),
        branch_id: "feature".into(),
        expected_head_digest: result.revision.revision_digest.clone(),
        upserts: Vec::new(),
        removals: vec![
            sekai_chisei::sekai::definition_branch::DefinitionMemberRef {
                member_kind: "object_type".into(),
                member_id: "Ticket".into(),
            },
        ],
        idempotency_key: "remove-1".into(),
    };
    let DefinitionWriteResult::ApplyEdit { result: removed } = db
        .apply_definition_branch_edit(&remove, "author", 6)
        .unwrap()
    else {
        panic!("expected branch removal");
    };
    assert_eq!(removed.changed_member_digests, [ticket_digest]);
    assert!(removed.revision.members.is_empty());

    let mut stale = edit.clone();
    stale.idempotency_key = "edit-stale".into();
    assert!(
        db.apply_definition_branch_edit(&stale, "author", 7)
            .unwrap_err()
            .contains("stale_definition_branch_head")
    );

    let mut conflicting_replay = create.clone();
    conflicting_replay.branch_id = "other".into();
    assert!(
        db.create_definition_branch(&conflicting_replay, "author", 8)
            .unwrap_err()
            .contains("definition_idempotency_conflict")
    );

    let mut unknown = create;
    unknown.branch_id = "unknown-parent".into();
    unknown.idempotency_key = "unknown-parent".into();
    unknown.parent_revision_digest = format!("sha256:{}", "a".repeat(64));
    assert!(
        db.create_definition_branch(&unknown, "author", 9)
            .unwrap_err()
            .contains("definition_revision_not_found")
    );
}

fn exercise_concurrent_stale_head(db: Arc<dyn DefinitionBranchBackend>, namespace: &str) {
    let (parent_digest, create) = seed(db.as_ref(), namespace);
    db.create_definition_branch(&create, "author", 2).unwrap();
    let barrier = Arc::new(Barrier::new(3));
    let handles = ["Project", "Incident"].map(|member_id| {
        let db = Arc::clone(&db);
        let barrier = Arc::clone(&barrier);
        let namespace = namespace.to_string();
        let parent_digest = parent_digest.clone();
        std::thread::spawn(move || {
            let request = ApplyDefinitionBranchEdit {
                namespace: namespace.clone(),
                branch_id: "feature".into(),
                expected_head_digest: parent_digest,
                upserts: vec![member(
                    &namespace,
                    member_id,
                    &format!(r#"{{"name":"{member_id}"}}"#),
                )],
                removals: Vec::new(),
                idempotency_key: format!("edit-{member_id}"),
            };
            barrier.wait();
            db.apply_definition_branch_edit(&request, "author", 3)
        })
    });
    barrier.wait();
    let results = handles.map(|handle| handle.join().unwrap());
    assert_eq!(results.iter().filter(|result| result.is_ok()).count(), 1);
    assert_eq!(
        results
            .iter()
            .filter(|result| {
                result
                    .as_ref()
                    .is_err_and(|error| error.contains("stale_definition_branch_head"))
            })
            .count(),
        1
    );
}

#[test]
fn sqlite_definition_branch_backend_conformance() {
    exercise_backend(&SekaiDb::new(":memory:").unwrap(), "sqlite-definition");
    exercise_concurrent_stale_head(
        Arc::new(SekaiDb::new(":memory:").unwrap()),
        "sqlite-definition-concurrent",
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
fn postgres_definition_branch_backend_conformance() {
    let prefix = format!("pg-definition-{}", uuid::Uuid::new_v4().simple());
    let db = Arc::new(postgres());
    exercise_backend(db.as_ref(), &prefix);
    exercise_concurrent_stale_head(db, &format!("{prefix}-concurrent"));
}
