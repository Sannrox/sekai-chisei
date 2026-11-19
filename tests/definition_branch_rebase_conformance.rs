//! Rebase and archive of definition branches behave the same on SQLite and
//! PostgreSQL (#2434).

use sekai_chisei::db::definition_branch::DefinitionBranchBackend;
use sekai_chisei::db::sekai::SekaiDb;
use sekai_chisei::sekai::definition_branch::{
    ApplyDefinitionBranchEdit, DefinitionBranch, DefinitionMemberRef, DefinitionWriteResult,
};
use sekai_chisei::sekai::definition_branch_rebase::{
    DefinitionBranchArchiveResult, DefinitionBranchRebaseResult, RebaseChoice,
    RebaseDefinitionBranch, RebaseResolution, SetDefinitionBranchArchived,
};
use sekai_chisei::sekai::definition_proposal::{
    CLOSE_REASON_OPERATOR_ABORT, CLOSE_REASON_SUPERSEDED, CreateDefinitionProposal, STATUS_CLOSED,
    STATUS_OPEN,
};

use crate::definition_branch_backend_conformance::{
    member, postgres, publish_revision, seed, typed_member,
};

fn edit(
    db: &dyn DefinitionBranchBackend,
    namespace: &str,
    branch: &DefinitionBranch,
    upserts: &[(&str, &str)],
    key: &str,
) -> String {
    let DefinitionWriteResult::ApplyEdit { result } = db
        .apply_definition_branch_edit(
            &ApplyDefinitionBranchEdit {
                namespace: namespace.into(),
                branch_id: branch.branch_id.clone(),
                expected_head_digest: branch.head_revision_digest.clone(),
                upserts: upserts
                    .iter()
                    .map(|(id, json)| member(namespace, id, json))
                    .collect(),
                removals: Vec::new(),
                idempotency_key: key.into(),
            },
            "author",
            10,
        )
        .unwrap()
    else {
        panic!("expected branch edit");
    };
    result.revision.revision_digest
}

fn propose(
    db: &dyn DefinitionBranchBackend,
    namespace: &str,
    branch: &DefinitionBranch,
    proposal_id: &str,
) -> Result<DefinitionWriteResult, String> {
    db.create_definition_proposal(
        &CreateDefinitionProposal {
            namespace: namespace.into(),
            branch_id: branch.branch_id.clone(),
            proposal_id: proposal_id.into(),
            base_digest: branch.base_revision_digest.clone(),
            candidate_digest: branch.head_revision_digest.clone(),
            eval_plan_digests: Vec::new(),
            named_foreign_digests: Vec::new(),
            idempotency_key: format!("{proposal_id}-create"),
            major_revision: false,
            migration_plan_digest: String::new(),
            dataset_proposals: Vec::new(),
            tenant: String::new(),
        },
        "author",
        11,
    )
}

fn branch(db: &dyn DefinitionBranchBackend, namespace: &str, branch_id: &str) -> DefinitionBranch {
    db.get_definition_branch(namespace, branch_id)
        .unwrap()
        .unwrap()
}

fn rebase(
    db: &dyn DefinitionBranchBackend,
    request: &RebaseDefinitionBranch,
) -> DefinitionBranchRebaseResult {
    let DefinitionWriteResult::Rebase { result } =
        db.rebase_definition_branch(request, "author", 20).unwrap()
    else {
        panic!("expected rebase");
    };
    *result
}

fn archive(
    db: &dyn DefinitionBranchBackend,
    namespace: &str,
    archived: bool,
    key: &str,
) -> Result<DefinitionBranchArchiveResult, String> {
    let result = db.set_definition_branch_archived(
        &SetDefinitionBranchArchived {
            namespace: namespace.into(),
            branch_id: "feature".into(),
            archived,
            reason: if archived {
                "superseded by a new design".into()
            } else {
                String::new()
            },
            idempotency_key: key.into(),
        },
        "author",
        30,
    )?;
    let DefinitionWriteResult::SetArchived { result } = result else {
        panic!("expected archive result");
    };
    Ok(*result)
}

fn member_ids(db: &dyn DefinitionBranchBackend, namespace: &str, digest: &str) -> Vec<String> {
    db.get_definition_revision(namespace, digest)
        .unwrap()
        .unwrap()
        .members
        .into_iter()
        .map(|member| format!("{}={}", member.member_id, &member.member_digest[7..15]))
        .collect::<std::collections::BTreeSet<_>>()
        .into_iter()
        .collect()
}

fn exercise_rebase_and_archive(db: &dyn DefinitionBranchBackend, namespace: &str) {
    let (published_before, create) = seed(db, namespace);
    db.create_definition_branch(&create, "author", 2).unwrap();
    // The branch adds Order and changes Ticket, then opens a proposal.
    let feature = branch(db, namespace, "feature");
    edit(
        db,
        namespace,
        &feature,
        &[
            ("Order", r#"{"name":"Order"}"#),
            ("Ticket", r#"{"name":"Ticket","properties":["owner"]}"#),
        ],
        "feature-edit",
    );
    let feature = branch(db, namespace, "feature");
    propose(db, namespace, &feature, "feature-1").unwrap();

    // A second branch only adds Shipment.
    db.create_definition_branch(
        &sekai_chisei::sekai::definition_branch::CreateDefinitionBranch {
            branch_id: "clean".into(),
            idempotency_key: "clean-create".into(),
            ..create.clone()
        },
        "author",
        3,
    )
    .unwrap();
    let clean = branch(db, namespace, "clean");
    edit(
        db,
        namespace,
        &clean,
        &[("Shipment", r#"{"name":"Shipment"}"#)],
        "clean-edit",
    );

    // Meanwhile another change publishes Ticket differently and adds InvoiceClass.
    let (published, _) = publish_revision(
        db,
        namespace,
        &published_before,
        "other",
        "other-1",
        vec![
            member(
                namespace,
                "Ticket",
                r#"{"name":"Ticket","properties":["title"]}"#,
            ),
            typed_member(
                namespace,
                "ontology_class",
                "InvoiceClass",
                r#"{"name":"InvoiceClass"}"#,
            ),
        ],
        4,
    );
    let feature = branch(db, namespace, "feature");
    assert!(
        propose(db, namespace, &feature, "feature-stale")
            .unwrap_err()
            .starts_with("stale_published_definition_head")
    );

    // Members that differ rebase cleanly.
    let clean = branch(db, namespace, "clean");
    let clean_rebase = RebaseDefinitionBranch {
        namespace: namespace.into(),
        branch_id: "clean".into(),
        expected_head_digest: clean.head_revision_digest.clone(),
        onto_published_digest: published.clone(),
        resolutions: Vec::new(),
        dry_run: false,
        idempotency_key: "clean-rebase".into(),
    };
    let rebased = rebase(db, &clean_rebase);
    assert!(rebased.applied && rebased.conflicts.is_empty());
    let clean = branch(db, namespace, "clean");
    assert_eq!(clean.base_revision_digest, published);
    let mut expected = member_ids(db, namespace, &published);
    expected.extend(
        member_ids(db, namespace, &rebased.previous_head_digest)
            .into_iter()
            .filter(|id| id.starts_with("Shipment")),
    );
    expected.sort();
    assert_eq!(
        member_ids(db, namespace, &clean.head_revision_digest),
        expected
    );
    propose(db, namespace, &clean, "clean-1").unwrap();

    // Ticket changed on both sides: a conflict, and nothing is written,
    // whether or not it is a dry run.
    let mut request = RebaseDefinitionBranch {
        branch_id: "feature".into(),
        expected_head_digest: feature.head_revision_digest.clone(),
        idempotency_key: "feature-rebase".into(),
        ..clean_rebase
    };
    for dry_run in [true, false] {
        request.dry_run = dry_run;
        let outcome = rebase(db, &request);
        assert!(!outcome.applied);
        assert_eq!(outcome.revision, None);
        assert_eq!(
            outcome
                .conflicts
                .iter()
                .map(|c| c.member_id.as_str())
                .collect::<Vec<_>>(),
            ["Ticket"]
        );
        assert_eq!(branch(db, namespace, "feature"), feature);
    }

    // A dry run with the resolution previews the rebased head and stores nothing.
    request.resolutions = vec![RebaseResolution {
        member_kind: "object_type".into(),
        member_id: "Ticket".into(),
        choice: RebaseChoice::KeepBranch,
    }];
    request.dry_run = true;
    let preview = rebase(db, &request);
    let previewed = preview.revision.clone().unwrap();
    assert!(!preview.applied);
    assert_eq!(previewed.parent_revision_digest, published);
    assert!(
        db.get_definition_revision(namespace, &previewed.revision_digest)
            .unwrap()
            .is_none()
    );
    assert_eq!(branch(db, namespace, "feature"), feature);
    assert_eq!(
        preview.changed_members,
        [DefinitionMemberRef {
            member_kind: "ontology_class".into(),
            member_id: "InvoiceClass".into()
        }]
    );

    // The real rebase writes that revision and supersedes the open proposal.
    request.dry_run = false;
    let rebased = rebase(db, &request);
    assert!(rebased.applied);
    assert_eq!(
        rebased.revision.as_ref().unwrap().revision_digest,
        previewed.revision_digest
    );
    assert_eq!(rebased.superseded_proposal_ids, ["feature-1"]);
    let old = db
        .get_definition_proposal(namespace, "feature-1")
        .unwrap()
        .unwrap();
    assert_eq!(
        (old.status.as_str(), old.close_reason_code.as_str()),
        (STATUS_CLOSED, CLOSE_REASON_SUPERSEDED)
    );
    let feature = branch(db, namespace, "feature");
    assert_eq!(feature.base_revision_digest, published);
    assert_eq!(feature.head_revision_digest, previewed.revision_digest);
    // A retry, real or dry, replays the rebase.
    assert_eq!(rebase(db, &request), rebased);
    request.dry_run = true;
    assert_eq!(rebase(db, &request), rebased);
    propose(db, namespace, &feature, "feature-2").unwrap();

    // Archive closes open work and refuses changes until restored.
    let archived = archive(db, namespace, true, "archive-1").unwrap();
    assert_eq!(archived.closed_proposal_ids, ["feature-2"]);
    assert_eq!(archived.branch.archive_reason, "superseded by a new design");
    let closed = db
        .get_definition_proposal(namespace, "feature-2")
        .unwrap()
        .unwrap();
    assert_eq!(closed.close_reason_code, CLOSE_REASON_OPERATOR_ABORT);
    assert_eq!(archive(db, namespace, true, "archive-1").unwrap(), archived);
    assert!(
        archive(db, namespace, true, "archive-2")
            .unwrap_err()
            .starts_with("definition_branch_archived")
    );
    let archived_branch = branch(db, namespace, "feature");
    assert!(
        propose(db, namespace, &archived_branch, "feature-3")
            .unwrap_err()
            .starts_with("definition_branch_archived")
    );
    let refused = db
        .apply_definition_branch_edit(
            &ApplyDefinitionBranchEdit {
                namespace: namespace.into(),
                branch_id: "feature".into(),
                expected_head_digest: archived_branch.head_revision_digest.clone(),
                upserts: vec![member(
                    namespace,
                    "Order",
                    r#"{"name":"Order","properties":["total"]}"#,
                )],
                removals: Vec::new(),
                idempotency_key: "archived-edit".into(),
            },
            "author",
            31,
        )
        .unwrap_err();
    assert!(
        refused.starts_with("definition_branch_archived"),
        "{refused}"
    );

    // Restore puts the branch back as it was; closed proposals stay closed.
    let restored = archive(db, namespace, false, "restore-1").unwrap();
    assert_eq!(
        DefinitionBranch {
            updated_at_ms: feature.updated_at_ms,
            ..restored.branch
        },
        feature
    );
    assert!(restored.closed_proposal_ids.is_empty());
    assert_eq!(
        db.get_definition_proposal(namespace, "feature-2")
            .unwrap()
            .unwrap()
            .status,
        STATUS_CLOSED
    );
    propose(
        db,
        namespace,
        &branch(db, namespace, "feature"),
        "feature-3",
    )
    .unwrap();
    assert_eq!(
        db.get_definition_proposal(namespace, "clean-1")
            .unwrap()
            .unwrap()
            .status,
        STATUS_OPEN
    );
}

#[test]
fn sqlite_definition_branch_rebase_conformance() {
    exercise_rebase_and_archive(&SekaiDb::new(":memory:").unwrap(), "sqlite-rebase");
}

#[test]
#[ignore = "requires SEKAI_TEST_POSTGRES_URL for an isolated TLS PostgreSQL database"]
fn postgres_definition_branch_rebase_conformance() {
    let namespace = format!("pg-rebase-{}", uuid::Uuid::new_v4().simple());
    exercise_rebase_and_archive(&postgres(), &namespace);
}
