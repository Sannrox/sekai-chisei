use std::sync::{Arc, Barrier};

use sekai_chisei::db::definition_branch::DefinitionBranchBackend;
use sekai_chisei::db::{postgres::PostgresDb, sekai::SekaiDb};
use sekai_chisei::sekai::definition_branch::{
    ApplyDefinitionBranchEdit, CreateDefinitionBranch, DefinitionMemberInput, DefinitionMemberRef,
    DefinitionRevisionMember, DefinitionWriteResult, prepare_revision,
};
use sekai_chisei::sekai::definition_diff::{
    classify_definition_revision_compatibility, compare_definition_revisions,
};
use sekai_chisei::sekai::definition_proposal::{
    ApproveDefinitionProposal, CLOSE_REASON_SUPERSEDED, CloseDefinitionProposal,
    CreateDefinitionProposal, MergeDefinitionProposal, STATUS_CLOSED, STATUS_MERGED, STATUS_OPEN,
};

fn member(namespace: &str, member_id: &str, definition_json: &str) -> DefinitionMemberInput {
    typed_member(namespace, "object_type", member_id, definition_json)
}

fn typed_member(
    namespace: &str,
    member_kind: &str,
    member_id: &str,
    definition_json: &str,
) -> DefinitionMemberInput {
    let mut input = DefinitionMemberInput {
        member_kind: member_kind.into(),
        member_id: member_id.into(),
        definition_json: definition_json.into(),
        member_digest: String::new(),
    };
    input.member_digest = input.prepare(namespace).unwrap().member_digest;
    input
}

fn digest(byte: char) -> String {
    format!("sha256:{}", byte.to_string().repeat(64))
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

fn exercise_proposal_publish(db: &dyn DefinitionBranchBackend, namespace: &str) {
    let (parent_digest, create) = seed(db, namespace);
    db.create_definition_branch(&create, "author", 2).unwrap();
    let edit = ApplyDefinitionBranchEdit {
        namespace: namespace.into(),
        branch_id: "feature".into(),
        expected_head_digest: parent_digest.clone(),
        upserts: vec![
            member(
                namespace,
                "Ticket",
                r#"{"name":"Ticket","properties":["title"]}"#,
            ),
            typed_member(
                namespace,
                "ontology_class",
                "TicketClass",
                r#"{"name":"TicketClass"}"#,
            ),
            typed_member(
                namespace,
                "action_type",
                "AssignTicket",
                r#"{"name":"AssignTicket"}"#,
            ),
        ],
        removals: Vec::new(),
        idempotency_key: "edit-publish".into(),
    };
    let DefinitionWriteResult::ApplyEdit { result } =
        db.apply_definition_branch_edit(&edit, "author", 3).unwrap()
    else {
        panic!("expected branch edit");
    };
    let candidate = result.revision.revision_digest.clone();
    let eval_digest = digest('e');
    let foreign_digest = digest('f');
    let propose = CreateDefinitionProposal {
        namespace: namespace.into(),
        branch_id: "feature".into(),
        proposal_id: "cs-1".into(),
        base_digest: parent_digest.clone(),
        candidate_digest: candidate.clone(),
        eval_plan_digests: vec![eval_digest.clone()],
        named_foreign_digests: vec![foreign_digest.clone()],
        idempotency_key: "propose-1".into(),
    };
    let created = db
        .create_definition_proposal(&propose, "author", 4)
        .unwrap();
    assert_eq!(
        created,
        db.create_definition_proposal(&propose, "author", 5)
            .unwrap()
    );
    let DefinitionWriteResult::CreateProposal { proposal } = created else {
        panic!("expected proposal create");
    };
    assert_eq!(proposal.status, STATUS_OPEN);
    assert_eq!(proposal.eval_plan_digests, [eval_digest]);
    assert_eq!(proposal.named_foreign_digests, [foreign_digest]);

    let merge = MergeDefinitionProposal {
        namespace: namespace.into(),
        proposal_id: "cs-1".into(),
        expected_published_digest: parent_digest.clone(),
        idempotency_key: "merge-missing".into(),
    };
    assert!(
        db.merge_definition_proposal(&merge, "author", 6)
            .unwrap_err()
            .contains("definition_proposal_missing_approval")
    );
    assert_eq!(
        db.get_published_definition_revision(namespace)
            .unwrap()
            .unwrap()
            .revision_digest,
        parent_digest
    );

    let approve = ApproveDefinitionProposal {
        namespace: namespace.into(),
        proposal_id: "cs-1".into(),
        idempotency_key: "approve-1".into(),
    };
    db.approve_definition_proposal(&approve, "author", 7)
        .unwrap();

    let stale_edit = ApplyDefinitionBranchEdit {
        namespace: namespace.into(),
        branch_id: "feature".into(),
        expected_head_digest: candidate.clone(),
        upserts: vec![member(
            namespace,
            "Ticket",
            r#"{"name":"Ticket","properties":["title","body"]}"#,
        )],
        removals: Vec::new(),
        idempotency_key: "edit-after-propose".into(),
    };
    db.apply_definition_branch_edit(&stale_edit, "author", 8)
        .unwrap();
    let stale_merge = MergeDefinitionProposal {
        namespace: namespace.into(),
        proposal_id: "cs-1".into(),
        expected_published_digest: parent_digest.clone(),
        idempotency_key: "merge-stale".into(),
    };
    assert!(
        db.merge_definition_proposal(&stale_merge, "author", 9)
            .unwrap_err()
            .contains("stale_definition_proposal_candidate")
    );
    assert_eq!(
        db.get_published_definition_revision(namespace)
            .unwrap()
            .unwrap()
            .revision_digest,
        parent_digest
    );

    let second_branch = CreateDefinitionBranch {
        namespace: namespace.into(),
        branch_id: "feature-2".into(),
        parent_revision_digest: parent_digest.clone(),
        idempotency_key: "create-2".into(),
    };
    db.create_definition_branch(&second_branch, "author", 11)
        .unwrap();
    let second_edit = ApplyDefinitionBranchEdit {
        namespace: namespace.into(),
        branch_id: "feature-2".into(),
        expected_head_digest: parent_digest.clone(),
        upserts: vec![
            member(
                namespace,
                "Ticket",
                r#"{"name":"Ticket","properties":["title"]}"#,
            ),
            typed_member(
                namespace,
                "ontology_class",
                "TicketClass",
                r#"{"name":"TicketClass"}"#,
            ),
            typed_member(
                namespace,
                "action_type",
                "AssignTicket",
                r#"{"name":"AssignTicket"}"#,
            ),
        ],
        removals: Vec::new(),
        idempotency_key: "edit-republish".into(),
    };
    let DefinitionWriteResult::ApplyEdit { result: second } = db
        .apply_definition_branch_edit(&second_edit, "author", 12)
        .unwrap()
    else {
        panic!("expected second edit");
    };
    let second_propose = CreateDefinitionProposal {
        namespace: namespace.into(),
        branch_id: "feature-2".into(),
        proposal_id: "cs-2".into(),
        base_digest: parent_digest.clone(),
        candidate_digest: second.revision.revision_digest.clone(),
        eval_plan_digests: vec![digest('e')],
        named_foreign_digests: vec![digest('f')],
        idempotency_key: "propose-2".into(),
    };
    db.create_definition_proposal(&second_propose, "author", 13)
        .unwrap();
    db.approve_definition_proposal(
        &ApproveDefinitionProposal {
            namespace: namespace.into(),
            proposal_id: "cs-2".into(),
            idempotency_key: "approve-2".into(),
        },
        "author",
        14,
    )
    .unwrap();
    let stale_expected = db
        .merge_definition_proposal(
            &MergeDefinitionProposal {
                namespace: namespace.into(),
                proposal_id: "cs-2".into(),
                expected_published_digest: second.revision.revision_digest.clone(),
                idempotency_key: "merge-stale-head".into(),
            },
            "author",
            15,
        )
        .unwrap_err();
    assert!(stale_expected.contains("stale_published_definition_head"));
    assert_eq!(
        db.get_published_definition_revision(namespace)
            .unwrap()
            .unwrap()
            .revision_digest,
        parent_digest
    );

    let merge_request = MergeDefinitionProposal {
        namespace: namespace.into(),
        proposal_id: "cs-2".into(),
        expected_published_digest: parent_digest.clone(),
        idempotency_key: "merge-2".into(),
    };
    let merged = db
        .merge_definition_proposal(&merge_request, "author", 16)
        .unwrap();
    assert_eq!(
        merged,
        db.merge_definition_proposal(&merge_request, "author", 17)
            .unwrap()
    );
    let DefinitionWriteResult::MergeProposal { result } = merged else {
        panic!("expected merge");
    };
    assert_eq!(result.proposal.status, STATUS_MERGED);
    assert!(!result.receipt_id.is_empty());
    assert_eq!(result.proposal.receipt_id, result.receipt_id);
    assert_eq!(result.previous_published_digest, parent_digest);
    assert!(result.published_revision.published);
    assert_eq!(
        db.get_published_definition_revision(namespace)
            .unwrap()
            .unwrap()
            .revision_digest,
        second.revision.revision_digest
    );
    let replayed_head = db
        .get_published_definition_revision(namespace)
        .unwrap()
        .unwrap()
        .revision_digest;
    db.merge_definition_proposal(&merge_request, "author", 18)
        .unwrap();
    assert_eq!(
        db.get_published_definition_revision(namespace)
            .unwrap()
            .unwrap()
            .revision_digest,
        replayed_head
    );
    assert_eq!(
        db.get_published_definition_revision(namespace)
            .unwrap()
            .unwrap()
            .revision_digest,
        second.revision.revision_digest
    );
    assert!(
        result
            .published_revision
            .members
            .iter()
            .any(|member| member.member_kind == "ontology_class")
    );
    assert!(
        result
            .published_revision
            .members
            .iter()
            .any(|member| member.member_kind == "action_type")
    );
    assert!(
        !result
            .published_revision
            .members
            .iter()
            .any(|member| member.member_digest == digest('f'))
    );

    let closed = db
        .close_definition_proposal(
            &CloseDefinitionProposal {
                namespace: namespace.into(),
                proposal_id: "cs-1".into(),
                reason_code: CLOSE_REASON_SUPERSEDED.into(),
                idempotency_key: "close-1".into(),
            },
            "author",
            19,
        )
        .unwrap();
    let DefinitionWriteResult::CloseProposal { proposal } = closed else {
        panic!("expected close");
    };
    assert_eq!(proposal.status, STATUS_CLOSED);
    assert_eq!(proposal.close_reason_code, CLOSE_REASON_SUPERSEDED);
    assert!(
        db.merge_definition_proposal(
            &MergeDefinitionProposal {
                namespace: namespace.into(),
                proposal_id: "cs-1".into(),
                expected_published_digest: parent_digest.clone(),
                idempotency_key: "merge-closed".into(),
            },
            "author",
            20,
        )
        .unwrap_err()
        .contains("definition_proposal_not_open")
    );
    assert_eq!(
        db.get_published_definition_revision(namespace)
            .unwrap()
            .unwrap()
            .revision_digest,
        second.revision.revision_digest
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

fn exercise_revision_diff(db: &dyn DefinitionBranchBackend, namespace: &str) {
    let (parent_digest, create) = seed(db, namespace);
    db.create_definition_branch(&create, "author", 2).unwrap();
    let edit = ApplyDefinitionBranchEdit {
        namespace: namespace.into(),
        branch_id: "feature".into(),
        expected_head_digest: parent_digest.clone(),
        upserts: vec![
            member(
                namespace,
                "Ticket",
                r#"{"name":"Ticket","properties":["title","body"]}"#,
            ),
            typed_member(
                namespace,
                "action_type",
                "AssignTicket",
                r#"{"name":"AssignTicket"}"#,
            ),
            typed_member(namespace, "control", "retention", r#"{"mode":"strict"}"#),
        ],
        removals: Vec::new(),
        idempotency_key: "edit-diff".into(),
    };
    let DefinitionWriteResult::ApplyEdit { result } =
        db.apply_definition_branch_edit(&edit, "author", 3).unwrap()
    else {
        panic!("expected branch edit");
    };
    let from = db
        .get_definition_revision(namespace, &parent_digest)
        .unwrap()
        .unwrap();
    let to = db
        .get_definition_revision(namespace, &result.revision.revision_digest)
        .unwrap()
        .unwrap();
    let from_members = db
        .get_definition_members(namespace, &from.revision_digest)
        .unwrap();
    let to_members = db
        .get_definition_members(namespace, &to.revision_digest)
        .unwrap();
    let diff = compare_definition_revisions(&from, &from_members, &to, &to_members).unwrap();
    assert_eq!(
        diff.added
            .iter()
            .map(|change| change.member_id.as_str())
            .collect::<Vec<_>>(),
        ["AssignTicket", "retention"]
    );
    assert!(diff.removed.is_empty());
    assert_eq!(diff.changed.len(), 1);
    assert_eq!(diff.changed[0].member_id, "Ticket");
    assert_eq!(diff.changed[0].added_properties, ["body", "title"]);
    let replay = compare_definition_revisions(&from, &from_members, &to, &to_members).unwrap();
    assert_eq!(diff, replay);
    let missing = db
        .get_definition_revision(namespace, &format!("sha256:{}", "a".repeat(64)))
        .unwrap();
    assert!(missing.is_none());
}

fn exercise_revision_compatibility(db: &dyn DefinitionBranchBackend, namespace: &str) {
    let (parent_digest, create) = seed(db, namespace);
    db.create_definition_branch(&create, "author", 2).unwrap();
    let compatible_edit = ApplyDefinitionBranchEdit {
        namespace: namespace.into(),
        branch_id: "feature".into(),
        expected_head_digest: parent_digest.clone(),
        upserts: vec![
            member(
                namespace,
                "Ticket",
                r#"{"name":"Ticket","properties":["title"]}"#,
            ),
            typed_member(
                namespace,
                "link_type",
                "AssignedTo",
                r#"{"name":"AssignedTo"}"#,
            ),
        ],
        removals: Vec::new(),
        idempotency_key: "edit-compatible".into(),
    };
    let DefinitionWriteResult::ApplyEdit { result: compatible } = db
        .apply_definition_branch_edit(&compatible_edit, "author", 3)
        .unwrap()
    else {
        panic!("expected branch edit");
    };
    let from = db
        .get_definition_revision(namespace, &parent_digest)
        .unwrap()
        .unwrap();
    let compatible_to = db
        .get_definition_revision(namespace, &compatible.revision.revision_digest)
        .unwrap()
        .unwrap();
    let from_members = db
        .get_definition_members(namespace, &from.revision_digest)
        .unwrap();
    let compatible_members = db
        .get_definition_members(namespace, &compatible_to.revision_digest)
        .unwrap();
    let compatible_report = classify_definition_revision_compatibility(
        &from,
        &from_members,
        &compatible_to,
        &compatible_members,
    )
    .unwrap();
    assert_eq!(compatible_report.class, "compatible");
    let replay = classify_definition_revision_compatibility(
        &from,
        &from_members,
        &compatible_to,
        &compatible_members,
    )
    .unwrap();
    assert_eq!(compatible_report, replay);

    let mixed_edit = ApplyDefinitionBranchEdit {
        namespace: namespace.into(),
        branch_id: "feature".into(),
        expected_head_digest: compatible.revision.revision_digest.clone(),
        upserts: vec![
            member(
                namespace,
                "Ticket",
                r#"{"name":"Ticket","properties":["title"],"required":["title"],"access_marking":"restricted"}"#,
            ),
            typed_member(namespace, "action_type", "Assign", r#"{"name":"Assign"}"#),
            typed_member(namespace, "control", "retention", r#"{"mode":"strict"}"#),
        ],
        removals: vec![DefinitionMemberRef {
            member_kind: "link_type".into(),
            member_id: "AssignedTo".into(),
        }],
        idempotency_key: "edit-breaking".into(),
    };
    let DefinitionWriteResult::ApplyEdit { result: mixed } = db
        .apply_definition_branch_edit(&mixed_edit, "author", 4)
        .unwrap()
    else {
        panic!("expected branch edit");
    };
    let mixed_to = db
        .get_definition_revision(namespace, &mixed.revision.revision_digest)
        .unwrap()
        .unwrap();
    let mixed_members = db
        .get_definition_members(namespace, &mixed_to.revision_digest)
        .unwrap();
    let mixed_report = classify_definition_revision_compatibility(
        &compatible_to,
        &compatible_members,
        &mixed_to,
        &mixed_members,
    )
    .unwrap();
    assert_eq!(mixed_report.class, "breaking");
    assert!(
        mixed_report
            .reasons
            .iter()
            .any(|reason| reason.code == "added_required_property")
    );
    assert!(
        mixed_report
            .reasons
            .iter()
            .any(|reason| reason.code == "removed_member" && reason.member_id == "AssignedTo")
    );
    assert!(
        mixed_report
            .reasons
            .iter()
            .any(|reason| reason.code == "added_action_type")
    );
    assert!(
        mixed_report
            .reasons
            .iter()
            .any(|reason| reason.code == "changed_marking")
    );
}

#[test]
fn sqlite_definition_branch_backend_conformance() {
    exercise_backend(&SekaiDb::new(":memory:").unwrap(), "sqlite-definition");
    exercise_proposal_publish(&SekaiDb::new(":memory:").unwrap(), "sqlite-proposal");
    exercise_revision_diff(&SekaiDb::new(":memory:").unwrap(), "sqlite-diff");
    exercise_revision_compatibility(&SekaiDb::new(":memory:").unwrap(), "sqlite-compat");
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
    exercise_proposal_publish(db.as_ref(), &format!("{prefix}-proposal"));
    exercise_revision_diff(db.as_ref(), &format!("{prefix}-diff"));
    exercise_revision_compatibility(db.as_ref(), &format!("{prefix}-compat"));
    exercise_concurrent_stale_head(db, &format!("{prefix}-concurrent"));
}
