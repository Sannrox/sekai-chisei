#[path = "../examples/definition_change_tracer.rs"]
mod fixture;

#[test]
fn definition_change_tracer_covers_define_ingest_link_propose_and_approve() {
    let report = fixture::run().expect("definition-change tracer should complete locally");
    let second = fixture::run().expect("definition-change tracer should repeat from empty state");

    assert_eq!(
        report.contract_version,
        "example.definition-change-tracer/v1"
    );
    assert_eq!(
        report.source_contract_version,
        "example.definition-change-tracer-source/v1"
    );
    assert_eq!(report.namespace, "acme");
    assert_eq!(report.agent_principal, "tester");
    assert_eq!(report.human_principal, "root");
    assert_eq!(report.branch_id, "tracer");
    assert_eq!(report.proposal_id, "tracer-proposal");
    assert_eq!(report.ingested_object_ids.len(), 2);
    assert_eq!(report.ingested_object_ids, second.ingested_object_ids);
    assert!(!report.parent_revision_digest.is_empty());
    assert!(!report.candidate_revision_digest.is_empty());
    assert_ne!(
        report.parent_revision_digest,
        report.candidate_revision_digest
    );
    assert!(!report.source_transaction_id.is_empty());
    assert!(!report.link_id.is_empty());
    assert!(!report.proposal_digest.is_empty());
    assert_eq!(report.approval_actor, "root");
    assert!(!report.merge_receipt_id.is_empty());
    assert!(report.agent_approve_denied);
    assert_eq!(report.approval_actor, second.approval_actor);
    assert!(!second.merge_receipt_id.is_empty());
    assert!(second.agent_approve_denied);
}
