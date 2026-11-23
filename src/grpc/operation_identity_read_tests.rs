//! Operation identity on source-health and revision-history reads (#3087): a
//! source batch apply and a definition merge record the call's identity, and
//! the reads report it, so an operator joins them to receipts and object
//! changes without a timestamp search.

use super::*;
use crate::sekai::operation_correlation::OPERATION_METADATA;

fn with_identity<T>(payload: T, principal: &str, operation_id: Option<&str>) -> Request<T> {
    let mut request = with_named_principal(payload, principal);
    if let Some(operation_id) = operation_id {
        request.metadata_mut().insert(
            OPERATION_METADATA,
            MetadataValue::try_from(operation_id).unwrap(),
        );
    }
    request
}

#[tokio::test]
async fn a_source_batch_apply_reports_its_operation_identity_on_every_read() {
    let svc = service();
    let ns = "op-src";
    let producer = "connector/github-primary";
    seed_definition_parent(&svc, ns);
    grant_source_namespace(&svc, ns, "root", security::Role::Admin);
    grant_source_namespace(&svc, ns, producer, security::Role::Editor);
    let apply = |current: &str, next: &str, operation_id: Option<&str>| {
        svc.apply_source_batch(with_identity(
            ApplySourceBatchRequest {
                batch: Some(source_batch(ns, producer, current, next, next)),
            },
            producer,
            operation_id,
        ))
    };

    let first = apply("", "cursor:1", Some("op-sync-1"))
        .await
        .unwrap()
        .into_inner()
        .result
        .unwrap();
    assert_eq!(first.transaction.unwrap().operation_id, "op-sync-1");
    let object_id = first.records[0].object.as_ref().unwrap().object_id.clone();
    // A replay under another header still reports the identity of the call
    // that applied the batch.
    let replayed = apply("", "cursor:1", Some("op-retry"))
        .await
        .unwrap()
        .into_inner()
        .result
        .unwrap();
    assert_eq!(replayed.transaction.unwrap().operation_id, "op-sync-1");
    // Without a header the plane mints one.
    let minted = apply("cursor:1", "cursor:2", None)
        .await
        .unwrap()
        .into_inner()
        .result
        .unwrap()
        .transaction
        .unwrap()
        .operation_id;
    assert!(minted.starts_with("op-source-batch-"), "{minted}");

    let listed = svc
        .list_source_batch_transactions(with_named_principal(
            ListSourceBatchTransactionsRequest {
                namespace: ns.into(),
                source_instance: "acme/ops".into(),
                type_digest: SOURCE_TYPE_DIGEST.into(),
                page_size: 10,
                page_token: String::new(),
            },
            producer,
        ))
        .await
        .unwrap()
        .into_inner();
    let ids: std::collections::BTreeSet<_> = listed
        .transactions
        .iter()
        .map(|transaction| transaction.operation_id.as_str())
        .collect();
    assert_eq!(ids, ["op-sync-1", minted.as_str()].into());

    let health = svc
        .get_source_health(with_named_principal(
            GetSourceHealthRequest {
                namespace: ns.into(),
                source_instance: "acme/ops".into(),
                type_digest: SOURCE_TYPE_DIGEST.into(),
                delayed_after_ms: None,
            },
            "root",
        ))
        .await
        .unwrap()
        .into_inner()
        .health
        .unwrap();
    assert_eq!(health.operation_id, minted);

    let changes = svc
        .db
        .runtime()
        .list_object_changes(&object_id, 16, 0)
        .unwrap();
    assert!(
        changes
            .iter()
            .any(|change| change.operation_id == "op-sync-1"),
        "{changes:?}"
    );
}

#[tokio::test]
async fn a_definition_merge_reports_its_operation_identity_in_revision_history() {
    let svc = service();
    let ns = "op-defs";
    let parent = seed_definition_parent(&svc, ns);
    let member = |properties: &str| DefinitionMemberInput {
        member_kind: "object_type".into(),
        member_id: "Ticket".into(),
        definition_json: format!(r#"{{"name":"Ticket","properties":[{properties}]}}"#),
        member_digest: String::new(),
    };
    let first = propose_and_merge_definition_as(
        &svc,
        ns,
        &parent.revision_digest,
        "op-b1",
        "op-p1",
        vec![member(r#""title""#)],
        Some("op-merge-1"),
    )
    .await
    .unwrap()
    .published_revision
    .unwrap()
    .revision_digest;
    // A replay of the merge under another header keeps the recorded identity.
    svc.merge_definition_proposal(with_identity(
        MergeDefinitionProposalRequest {
            namespace: ns.into(),
            proposal_id: "op-p1".into(),
            expected_published_digest: parent.revision_digest.clone(),
            idempotency_key: "op-b1-merge".into(),
        },
        "root",
        Some("op-retry"),
    ))
    .await
    .unwrap();
    propose_and_merge_definition_as(
        &svc,
        ns,
        &first,
        "op-b2",
        "op-p2",
        vec![member(r#""title","body""#)],
        None,
    )
    .await
    .unwrap();

    let entries = svc
        .list_published_definition_revisions(with_named_principal(
            ListPublishedDefinitionRevisionsRequest {
                namespace: ns.into(),
                member_kind: String::new(),
                member_id: String::new(),
                page_token: String::new(),
                page_size: 10,
            },
            "root",
        ))
        .await
        .unwrap()
        .into_inner()
        .entries;
    let by_proposal = |proposal: &str| {
        entries
            .iter()
            .find(|entry| entry.proposal_id == proposal)
            .unwrap()
            .operation_id
            .clone()
    };
    assert_eq!(by_proposal("op-p1"), "op-merge-1");
    let minted = by_proposal("op-p2");
    assert!(minted.starts_with("op-definition-merge-"), "{minted}");
}
