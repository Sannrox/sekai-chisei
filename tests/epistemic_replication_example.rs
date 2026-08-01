#[path = "../examples/epistemic_replication.rs"]
mod fixture;

#[test]
fn deterministic_replication_fixture_covers_the_governed_surfaces() {
    let report = fixture::run().expect("replication fixture should complete locally");
    let second_report = fixture::run().expect("replication fixture should repeat locally");

    assert_eq!(report.contract_version, "example.epistemic-replication/v1");
    assert_eq!(report.domain_class_count, 8);
    assert_eq!(report.seeded_object_count, 12);
    assert_eq!(report.independent_result_producers.len(), 2);
    assert_eq!(report.evidence_fixture_states["supporting"], "available");
    assert_eq!(report.evidence_fixture_states["contradicting"], "available");
    assert_eq!(report.evidence_fixture_states["stale"], "stale");
    assert_eq!(report.evidence_fixture_states["retracted"], "retracted");
    assert_eq!(report.contested_descriptor_status, "contested");
    assert_eq!(report.insufficient_descriptor_status, "insufficient");
    assert_eq!(
        report.kioku_evidence_stances,
        ["supporting", "contradicting"]
    );
    assert_eq!(report.kioku_state_before_review, "candidate");
    assert_eq!(report.kioku_state_after_review, "active");
    assert!(report.superseded);
    assert_eq!(
        report.epistemic_comparison.fixture_digest,
        second_report.epistemic_comparison.fixture_digest
    );
    assert_eq!(
        report.epistemic_case_digests,
        second_report.epistemic_case_digests
    );
    assert_eq!(report.kioku_policy_action, "require_review");
    assert_eq!(report.unknown_policy_action, "hold_out");
    assert_eq!(report.stale_policy_action, "hold_out");
    assert!(report.governed_subject_fresh);
    assert_eq!(report.governed_subject_claim_only_decision, "allow");
    assert_eq!(report.epistemic_framed_context_action, "include");
    assert_eq!(report.stale_governed_subject_decision, "unknown");
    assert_eq!(report.evaluation_step_status, "pass");
    assert_eq!(report.evaluation_verdict, "allow");
    assert!(report.evaluation_step_receipt_digest.starts_with("sha256:"));
    assert!(
        report
            .evaluation_gate_decision_digest
            .starts_with("sha256:")
    );
    assert_eq!(report.epistemic_case_digests.len(), 6);
    assert!(report.epistemic_case_digests.iter().all(|case| {
        case.baseline_receipt_digest.starts_with("sha256:")
            && case.baseline_outcome_digest.starts_with("sha256:")
            && case.candidate_receipt_digest.starts_with("sha256:")
            && case.candidate_outcome_digest.starts_with("sha256:")
    }));
    assert_eq!(
        report.epistemic_comparison.baseline_config_ref,
        "kioku-context:claim-only:v1"
    );
    assert_eq!(
        report.epistemic_comparison.candidate_config_ref,
        "kioku-context:epistemic:v1"
    );
    assert_eq!(report.epistemic_comparison.regression_gate.verdict, "pass");
    assert!(report.epistemic_comparison.regression_gate.allowed);
    assert!(
        report
            .epistemic_comparison
            .candidate_metrics
            .calibration_error_micros
            < report
                .epistemic_comparison
                .baseline_metrics
                .calibration_error_micros
    );
}
