use std::sync::{Arc, Barrier};

use sekai_chisei::db::definition_branch::DefinitionBranchBackend;
use sekai_chisei::db::{postgres::PostgresDb, sekai::SekaiDb};
use sekai_chisei::sekai::definition_branch::{
    ApplyDefinitionBranchEdit, CreateDefinitionBranch, DefinitionMemberInput,
    DefinitionRevisionMember, DefinitionWriteResult, prepare_revision,
};
use sekai_chisei::sekai::definition_proposal::{
    ApproveDefinitionProposal, CreateDefinitionProposal, FrozenEvalPlanRef,
    MergeDefinitionProposal, RejectDefinitionProposal,
};

fn kinded_member(
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
    exercise_proposal_backend(db, namespace);
}

fn digest(byte: char) -> String {
    format!("sha256:{}", byte.to_string().repeat(64))
}

fn exercise_proposal_backend(db: &dyn DefinitionBranchBackend, namespace: &str) {
    let published = db
        .get_published_definition_head(namespace)
        .unwrap()
        .expect("seeded published head");
    let branch = db
        .get_definition_branch(namespace, "feature")
        .unwrap()
        .unwrap();
    let mixed = ApplyDefinitionBranchEdit {
        namespace: namespace.into(),
        branch_id: "feature".into(),
        expected_head_digest: branch.head_revision_digest.clone(),
        upserts: vec![
            kinded_member(
                namespace,
                "ontology_class",
                "TicketClass",
                r#"{"name":"TicketClass"}"#,
            ),
            kinded_member(namespace, "action_type", "assign", r#"{"name":"assign"}"#),
            kinded_member(namespace, "control", "retention", r#"{"mode":"strict"}"#),
        ],
        removals: Vec::new(),
        idempotency_key: "proposal-members".into(),
    };
    let DefinitionWriteResult::ApplyEdit { result: edited } = db
        .apply_definition_branch_edit(&mixed, "author", 20)
        .unwrap()
    else {
        panic!("expected mixed member edit");
    };

    let create = CreateDefinitionProposal {
        namespace: namespace.into(),
        branch_id: "feature".into(),
        proposal_id: "cs-1".into(),
        base_digest: published.clone(),
        candidate_digest: edited.revision.revision_digest.clone(),
        frozen_eval_plans: vec![FrozenEvalPlanRef {
            plan_id: "gate".into(),
            plan_digest: digest('e'),
        }],
        named_foreign_digests: vec![digest('f')],
        idempotency_key: "propose-1".into(),
    };
    let first = db
        .create_definition_proposal(&create, "author", 21)
        .unwrap();
    assert_eq!(
        first,
        db.create_definition_proposal(&create, "author", 22)
            .unwrap()
    );
    let DefinitionWriteResult::CreateProposal { proposal } = first else {
        panic!("expected proposal creation");
    };
    assert_eq!(proposal.status, "open");
    assert_eq!(
        db.get_definition_proposal(namespace, "feature", "cs-1")
            .unwrap()
            .unwrap(),
        proposal
    );

    let merge_unapproved = MergeDefinitionProposal {
        namespace: namespace.into(),
        branch_id: "feature".into(),
        proposal_id: "cs-1".into(),
        expected_proposal_digest: proposal.proposal_digest.clone(),
        expected_published_digest: published.clone(),
        idempotency_key: "merge-missing".into(),
    };
    assert!(
        db.merge_definition_proposal(&merge_unapproved, "author", 23)
            .unwrap_err()
            .contains("missing_approval")
    );

    let approve = ApproveDefinitionProposal {
        namespace: namespace.into(),
        branch_id: "feature".into(),
        proposal_id: "cs-1".into(),
        expected_proposal_digest: proposal.proposal_digest.clone(),
        idempotency_key: "approve-1".into(),
    };
    let DefinitionWriteResult::ApproveProposal { proposal: approved } = db
        .approve_definition_proposal(&approve, "reviewer", 24)
        .unwrap()
    else {
        panic!("expected approval");
    };
    assert_eq!(
        approved,
        match db
            .approve_definition_proposal(&approve, "reviewer", 25)
            .unwrap()
        {
            DefinitionWriteResult::ApproveProposal { proposal } => proposal,
            other => panic!("unexpected replay {other:?}"),
        }
    );

    let merge = MergeDefinitionProposal {
        namespace: namespace.into(),
        branch_id: "feature".into(),
        proposal_id: "cs-1".into(),
        expected_proposal_digest: approved.proposal_digest.clone(),
        expected_published_digest: published.clone(),
        idempotency_key: "merge-1".into(),
    };
    let merged = db.merge_definition_proposal(&merge, "author", 26).unwrap();
    assert_eq!(
        merged,
        db.merge_definition_proposal(&merge, "author", 27).unwrap()
    );
    let DefinitionWriteResult::MergeProposal { result } = merged else {
        panic!("expected merge");
    };
    assert_eq!(result.previous_published_digest, published);
    assert_eq!(result.published_digest, edited.revision.revision_digest);
    assert!(result.revision.published);
    assert_eq!(result.proposal.status, "merged");
    assert_eq!(
        db.get_published_definition_head(namespace)
            .unwrap()
            .unwrap(),
        result.published_digest
    );
    assert!(!result.receipt_id.is_empty());

    let reject_branch = CreateDefinitionBranch {
        namespace: namespace.into(),
        branch_id: "reject-me".into(),
        parent_revision_digest: result.published_digest.clone(),
        idempotency_key: "create-reject".into(),
    };
    db.create_definition_branch(&reject_branch, "author", 28)
        .unwrap();
    let reject_edit = ApplyDefinitionBranchEdit {
        namespace: namespace.into(),
        branch_id: "reject-me".into(),
        expected_head_digest: result.published_digest.clone(),
        upserts: vec![member(
            namespace,
            "Ticket",
            r#"{"name":"Ticket","rejected":true}"#,
        )],
        removals: Vec::new(),
        idempotency_key: "edit-reject".into(),
    };
    let DefinitionWriteResult::ApplyEdit {
        result: reject_edited,
    } = db
        .apply_definition_branch_edit(&reject_edit, "author", 29)
        .unwrap()
    else {
        panic!("expected reject-path edit");
    };
    let reject_create = CreateDefinitionProposal {
        namespace: namespace.into(),
        branch_id: "reject-me".into(),
        proposal_id: "cs-reject".into(),
        base_digest: result.published_digest.clone(),
        candidate_digest: reject_edited.revision.revision_digest.clone(),
        frozen_eval_plans: Vec::new(),
        named_foreign_digests: Vec::new(),
        idempotency_key: "propose-reject".into(),
    };
    let DefinitionWriteResult::CreateProposal {
        proposal: rejectable,
    } = db
        .create_definition_proposal(&reject_create, "author", 30)
        .unwrap()
    else {
        panic!("expected rejectable proposal");
    };
    let reject = RejectDefinitionProposal {
        namespace: namespace.into(),
        branch_id: "reject-me".into(),
        proposal_id: "cs-reject".into(),
        expected_proposal_digest: rejectable.proposal_digest.clone(),
        reason_code: "policy_denied".into(),
        idempotency_key: "reject-1".into(),
    };
    db.reject_definition_proposal(&reject, "reviewer", 31)
        .unwrap();
    let merge_rejected = MergeDefinitionProposal {
        namespace: namespace.into(),
        branch_id: "reject-me".into(),
        proposal_id: "cs-reject".into(),
        expected_proposal_digest: rejectable.proposal_digest,
        expected_published_digest: result.published_digest.clone(),
        idempotency_key: "merge-rejected".into(),
    };
    assert!(
        db.merge_definition_proposal(&merge_rejected, "author", 32)
            .unwrap_err()
            .contains("rejected")
    );

    assert!(
        db.create_definition_proposal(
            &CreateDefinitionProposal {
                namespace: namespace.into(),
                branch_id: "feature".into(),
                proposal_id: "cs-stale".into(),
                base_digest: published,
                candidate_digest: result.published_digest.clone(),
                frozen_eval_plans: Vec::new(),
                named_foreign_digests: Vec::new(),
                idempotency_key: "propose-stale".into(),
            },
            "author",
            33,
        )
        .unwrap_err()
        .contains("stale_base")
    );

    let change_branch = CreateDefinitionBranch {
        namespace: namespace.into(),
        branch_id: "changed-digest".into(),
        parent_revision_digest: result.published_digest.clone(),
        idempotency_key: "create-changed".into(),
    };
    db.create_definition_branch(&change_branch, "author", 34)
        .unwrap();
    let first_edit = ApplyDefinitionBranchEdit {
        namespace: namespace.into(),
        branch_id: "changed-digest".into(),
        expected_head_digest: result.published_digest.clone(),
        upserts: vec![member(namespace, "Ticket", r#"{"name":"Ticket","v":1}"#)],
        removals: Vec::new(),
        idempotency_key: "edit-changed-1".into(),
    };
    let DefinitionWriteResult::ApplyEdit {
        result: first_change,
    } = db
        .apply_definition_branch_edit(&first_edit, "author", 35)
        .unwrap()
    else {
        panic!("expected first changed-digest edit");
    };
    let change_create = CreateDefinitionProposal {
        namespace: namespace.into(),
        branch_id: "changed-digest".into(),
        proposal_id: "cs-changed".into(),
        base_digest: result.published_digest.clone(),
        candidate_digest: first_change.revision.revision_digest.clone(),
        frozen_eval_plans: Vec::new(),
        named_foreign_digests: Vec::new(),
        idempotency_key: "propose-changed".into(),
    };
    let DefinitionWriteResult::CreateProposal {
        proposal: changeable,
    } = db
        .create_definition_proposal(&change_create, "author", 36)
        .unwrap()
    else {
        panic!("expected changed-digest proposal");
    };
    db.approve_definition_proposal(
        &ApproveDefinitionProposal {
            namespace: namespace.into(),
            branch_id: "changed-digest".into(),
            proposal_id: "cs-changed".into(),
            expected_proposal_digest: changeable.proposal_digest.clone(),
            idempotency_key: "approve-changed".into(),
        },
        "reviewer",
        37,
    )
    .unwrap();
    db.apply_definition_branch_edit(
        &ApplyDefinitionBranchEdit {
            namespace: namespace.into(),
            branch_id: "changed-digest".into(),
            expected_head_digest: first_change.revision.revision_digest,
            upserts: vec![member(namespace, "Ticket", r#"{"name":"Ticket","v":2}"#)],
            removals: Vec::new(),
            idempotency_key: "edit-changed-2".into(),
        },
        "author",
        38,
    )
    .unwrap();
    assert!(
        db.merge_definition_proposal(
            &MergeDefinitionProposal {
                namespace: namespace.into(),
                branch_id: "changed-digest".into(),
                proposal_id: "cs-changed".into(),
                expected_proposal_digest: changeable.proposal_digest,
                expected_published_digest: result.published_digest.clone(),
                idempotency_key: "merge-changed".into(),
            },
            "author",
            39,
        )
        .unwrap_err()
        .contains("changed_digest")
    );

    let unrebased = CreateDefinitionBranch {
        namespace: namespace.into(),
        branch_id: "unrebased".into(),
        parent_revision_digest: result.published_digest.clone(),
        idempotency_key: "create-unrebased".into(),
    };
    db.create_definition_branch(&unrebased, "author", 40)
        .unwrap();
    let unrebased_edit = ApplyDefinitionBranchEdit {
        namespace: namespace.into(),
        branch_id: "unrebased".into(),
        expected_head_digest: result.published_digest.clone(),
        upserts: vec![member(
            namespace,
            "Ticket",
            r#"{"name":"Ticket","fork":true}"#,
        )],
        removals: Vec::new(),
        idempotency_key: "edit-unrebased".into(),
    };
    let DefinitionWriteResult::ApplyEdit {
        result: unrebased_head,
    } = db
        .apply_definition_branch_edit(&unrebased_edit, "author", 41)
        .unwrap()
    else {
        panic!("expected unrebased edit");
    };
    // The published head is already the merged candidate. A fork whose parent is
    // that head still descends. Create a second merge first so the fork is stale
    // relative to a newer published head that it does not descend from.
    let competing = CreateDefinitionBranch {
        namespace: namespace.into(),
        branch_id: "competing".into(),
        parent_revision_digest: result.published_digest.clone(),
        idempotency_key: "create-competing".into(),
    };
    db.create_definition_branch(&competing, "author", 42)
        .unwrap();
    let competing_edit = ApplyDefinitionBranchEdit {
        namespace: namespace.into(),
        branch_id: "competing".into(),
        expected_head_digest: result.published_digest.clone(),
        upserts: vec![member(
            namespace,
            "Ticket",
            r#"{"name":"Ticket","winner":true}"#,
        )],
        removals: Vec::new(),
        idempotency_key: "edit-competing".into(),
    };
    let DefinitionWriteResult::ApplyEdit {
        result: competing_head,
    } = db
        .apply_definition_branch_edit(&competing_edit, "author", 43)
        .unwrap()
    else {
        panic!("expected competing edit");
    };
    let competing_create = CreateDefinitionProposal {
        namespace: namespace.into(),
        branch_id: "competing".into(),
        proposal_id: "cs-competing".into(),
        base_digest: result.published_digest.clone(),
        candidate_digest: competing_head.revision.revision_digest.clone(),
        frozen_eval_plans: Vec::new(),
        named_foreign_digests: Vec::new(),
        idempotency_key: "propose-competing".into(),
    };
    let DefinitionWriteResult::CreateProposal {
        proposal: competing_proposal,
    } = db
        .create_definition_proposal(&competing_create, "author", 44)
        .unwrap()
    else {
        panic!("expected competing proposal");
    };
    db.approve_definition_proposal(
        &ApproveDefinitionProposal {
            namespace: namespace.into(),
            branch_id: "competing".into(),
            proposal_id: "cs-competing".into(),
            expected_proposal_digest: competing_proposal.proposal_digest.clone(),
            idempotency_key: "approve-competing".into(),
        },
        "reviewer",
        45,
    )
    .unwrap();
    let DefinitionWriteResult::MergeProposal {
        result: competing_merge,
    } = db
        .merge_definition_proposal(
            &MergeDefinitionProposal {
                namespace: namespace.into(),
                branch_id: "competing".into(),
                proposal_id: "cs-competing".into(),
                expected_proposal_digest: competing_proposal.proposal_digest,
                expected_published_digest: result.published_digest,
                idempotency_key: "merge-competing".into(),
            },
            "author",
            46,
        )
        .unwrap()
    else {
        panic!("expected competing merge");
    };
    assert!(
        db.create_definition_proposal(
            &CreateDefinitionProposal {
                namespace: namespace.into(),
                branch_id: "unrebased".into(),
                proposal_id: "cs-unrebased".into(),
                base_digest: competing_merge.published_digest,
                candidate_digest: unrebased_head.revision.revision_digest,
                frozen_eval_plans: Vec::new(),
                named_foreign_digests: Vec::new(),
                idempotency_key: "propose-unrebased".into(),
            },
            "author",
            47,
        )
        .unwrap_err()
        .contains("incompatible_candidate")
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
