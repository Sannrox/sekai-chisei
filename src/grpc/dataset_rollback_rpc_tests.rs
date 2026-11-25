//! Dataset rollback proposals (#3186) through the gRPC service: another
//! principal with write access applies a proposal exactly once, a denial
//! changes nothing, and the pending inbox lists exactly what the decide RPC
//! accepts.

use super::*;

const DATASET: &str = "rollback-ds";
const NAMESPACE: &str = "rollback-ns";

/// A dataset bound in `NAMESPACE` with two versions, oldest first. `tester`
/// administers it, `reviewer` edits it, `viewer` only reads.
async fn fixture(svc: &SekaiServiceImpl) -> Vec<String> {
    svc.db
        .runtime()
        .create_object(&crate::domain::Object {
            id: "rollback-binding".into(),
            kind: "widget".into(),
            name: "binding".into(),
            namespace: NAMESPACE.into(),
            external_id: String::new(),
            properties: HashMap::new(),
            created: 1,
            updated: 1,
        })
        .unwrap();
    grant_object_role(svc, "rollback-binding", "tester", security::Role::Admin);
    grant_object_role(svc, "rollback-binding", "reviewer", security::Role::Editor);
    grant_object_role(svc, "rollback-binding", "viewer", security::Role::Viewer);
    svc.create_dataset(with_principal(CreateDatasetRequest {
        dataset: Some(Dataset {
            id: DATASET.into(),
            name: DATASET.into(),
            columns: vec![ColumnDef {
                name: "kind".into(),
                r#type: "string".into(),
                classification: "public".into(),
            }],
            object_id: "rollback-binding".into(),
            created: 1,
            partition_keys: Vec::new(),
        }),
    }))
    .await
    .unwrap();
    for value in ["good", "bad"] {
        append(svc, value);
    }
    versions(svc)
}

fn append(svc: &SekaiServiceImpl, value: &str) {
    svc.db
        .runtime()
        .append_rows(DATASET, &[[("kind".to_string(), value.to_string())].into()])
        .unwrap();
}

fn versions(svc: &SekaiServiceImpl) -> Vec<String> {
    svc.db
        .runtime()
        .list_dataset_versions(DATASET)
        .unwrap()
        .into_iter()
        .map(|version| version.version_id)
        .collect()
}

async fn propose(svc: &SekaiServiceImpl, source: &str) -> DatasetRollbackProposal {
    svc.propose_dataset_rollback(with_principal(ProposeDatasetRollbackRequest {
        dataset_id: DATASET.into(),
        restore_from_version_id: source.into(),
        reason: "bad load".into(),
    }))
    .await
    .unwrap()
    .into_inner()
    .proposal
    .unwrap()
}

async fn decide(
    svc: &SekaiServiceImpl,
    proposal_id: &str,
    principal: &str,
    approve: bool,
) -> Result<DatasetRollbackProposal, Status> {
    svc.decide_dataset_rollback(with_named_principal(
        DecideDatasetRollbackRequest {
            dataset_id: DATASET.into(),
            proposal_id: proposal_id.into(),
            approve,
            reason: String::new(),
        },
        principal,
    ))
    .await
    .map(|response| response.into_inner().proposal.unwrap())
}

/// The proposal ids pending on `principal` in `namespace`.
async fn pending_on(svc: &SekaiServiceImpl, namespace: &str, principal: &str) -> Vec<String> {
    svc.list_pending_decisions(with_named_principal(
        ListPendingDecisionsRequest {
            namespace: namespace.into(),
            kinds: vec![PendingDecisionKind::DatasetRollbackProposal as i32],
            limit: 0,
            page_token: String::new(),
        },
        principal,
    ))
    .await
    .unwrap()
    .into_inner()
    .decisions
    .into_iter()
    .map(|decision| decision.subject_id)
    .collect()
}

#[tokio::test]
async fn a_second_principal_applies_a_rollback_once() {
    let svc = service();
    let before = fixture(&svc).await;
    let proposal = propose(&svc, &before[0]).await;
    assert_eq!(proposal.base_version_id, before[1]);

    // Pending only on the editor, and only under the binding's namespace.
    assert_eq!(
        pending_on(&svc, NAMESPACE, "reviewer").await,
        std::slice::from_ref(&proposal.id)
    );
    assert!(pending_on(&svc, "acme", "reviewer").await.is_empty());
    for outsider in ["tester", "viewer"] {
        assert!(pending_on(&svc, NAMESPACE, outsider).await.is_empty());
        let refused = decide(&svc, &proposal.id, outsider, true)
            .await
            .unwrap_err();
        assert_eq!(refused.code(), tonic::Code::PermissionDenied, "{outsider}");
    }
    assert_eq!(versions(&svc), before);

    let approved = decide(&svc, &proposal.id, "reviewer", true).await.unwrap();
    assert_eq!(approved.status, "approved");
    assert!(!approved.receipt_id.is_empty());
    let restored = svc
        .db
        .runtime()
        .list_dataset_versions(DATASET)
        .unwrap()
        .pop()
        .unwrap();
    assert_eq!(restored.version_id, approved.restored_version_id);
    assert_eq!(restored.restored_from_version_id, before[0]);
    assert!(pending_on(&svc, NAMESPACE, "reviewer").await.is_empty());

    // Deciding again returns the same proposal and writes no version.
    let replay = decide(&svc, &proposal.id, "reviewer", true).await.unwrap();
    assert_eq!(replay, approved);
    assert_eq!(versions(&svc).len(), 3);
    let read = svc
        .get_dataset_rollback_proposal(with_named_principal(
            GetDatasetRollbackProposalRequest {
                dataset_id: DATASET.into(),
                proposal_id: proposal.id.clone(),
            },
            "viewer",
        ))
        .await
        .unwrap()
        .into_inner()
        .proposal
        .unwrap();
    assert_eq!(read, approved);
}

#[tokio::test]
async fn a_denied_or_stale_rollback_changes_nothing() {
    let svc = service();
    let before = fixture(&svc).await;
    let denied = propose(&svc, &before[0]).await;
    let decision = decide(&svc, &denied.id, "reviewer", false).await.unwrap();
    assert_eq!(decision.status, "denied");
    assert_eq!(versions(&svc), before);
    assert!(pending_on(&svc, NAMESPACE, "reviewer").await.is_empty());
    let reversed = decide(&svc, &denied.id, "reviewer", true)
        .await
        .unwrap_err();
    assert_eq!(reversed.code(), tonic::Code::FailedPrecondition);

    // A version written after the proposal refuses the approval by name.
    let stale = propose(&svc, &before[0]).await;
    append(&svc, "newer");
    let refused = decide(&svc, &stale.id, "reviewer", true).await.unwrap_err();
    assert_eq!(refused.code(), tonic::Code::FailedPrecondition);
    assert_eq!(
        refused.message(),
        crate::sekai::dataset_rollback::PROPOSAL_STALE_BASE
    );
    assert_eq!(versions(&svc).len(), 3);

    // Both proposals list newest first, one per page. Proposals created in
    // the same millisecond tie-break by id, which is random (#3464).
    let (newer, older) = if (stale.created_at_ms, &stale.id) > (denied.created_at_ms, &denied.id) {
        (&stale, &denied)
    } else {
        (&denied, &stale)
    };
    let page = |token: String| {
        svc.list_dataset_rollback_proposals(with_principal(ListDatasetRollbackProposalsRequest {
            dataset_id: DATASET.into(),
            limit: 1,
            page_token: token,
        }))
    };
    let first = page(String::new()).await.unwrap().into_inner();
    assert_eq!(first.proposals[0].id, newer.id);
    let second = page(first.next_page_token).await.unwrap().into_inner();
    assert_eq!(second.proposals[0].id, older.id);
    assert_eq!(second.proposals.len(), 1);
    assert!(second.next_page_token.is_empty());
}
