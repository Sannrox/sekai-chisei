#[path = "../examples/source_writeback.rs"]
mod fixture;

#[test]
fn source_writeback_example_covers_sync_writeback_and_receipts() {
    let report = fixture::run().expect("source write-back fixture should complete locally");
    let second = fixture::run().expect("source write-back fixture should repeat from empty state");

    assert_eq!(report.contract_version, "example.source-writeback/v1");
    assert_eq!(report.source_identity, "github:acme/ops#42");
    assert_eq!(report.type_digest, fixture::GITHUB_TYPE_DIGEST);
    assert_eq!(report.object_id, second.object_id);
    assert_eq!(report.applied_effect_count, 1);
    assert_eq!(second.applied_effect_count, 1);
    assert!(report.object_id.starts_with("sync-"));
    assert!(!report.action_instance_id.is_empty());
    assert!(!report.permit_id.is_empty());
    assert!(!report.execution_id.is_empty());
    assert!(!report.receipt_operation_id.is_empty());
    assert!(!report.execution_evidence_id.is_empty());
    assert_eq!(report.readback_source_version, "issue-42-v4");
    assert!(report.stale_precondition_blocked);
    assert!(report.denied_authorization_blocked);
    assert!(report.identical_intent_replayed);
    assert!(report.changed_intent_rejected);
    assert_eq!(report.response_loss_outcome, "unknown");
    assert!(report.recovered_without_repeat);
    assert!(report.restart_preserved_identity);
    assert_eq!(report.fixture_effect_count_after_restart, 1);
}
