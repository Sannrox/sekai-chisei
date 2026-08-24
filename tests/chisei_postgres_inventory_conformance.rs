//! Inventory fail-closed checks for Chisei PostgreSQL parity.

use sekai_chisei::db::chisei_rpc_inventory::{
    ChiseiRpcInventory, postgres_complete_chisei_capabilities,
};
use sekai_chisei::runtime_backend::COMMUNITY_REQUIRED_SURFACES;

#[test]
fn chisei_inventory_covers_every_proto_rpc() {
    let inventory = ChiseiRpcInventory::load().expect("inventory must validate");
    assert_eq!(inventory.entries.len(), 31);
    assert!(inventory.entry("EvaluateGovernedSubject").is_some());
    assert!(inventory.entry("ExportGovernedSubjectProvenance").is_some());
    assert!(
        inventory
            .entry("GetGovernedSubjectProvenanceTrustRoot")
            .is_none()
    );
    assert!(inventory.entry("GetOperationReceipt").is_some());
    assert!(inventory.entry("PlanContentExecution").is_some());
    assert!(inventory.entry("ExecuteContentPlanStream").is_some());
    assert!(inventory.entry("GetEvaluationGateEvidence").is_some());
    assert!(inventory.entry("RunLookupFirstPromotionGate").is_some());
    assert!(inventory.entry("GetEvalSuite").is_none());
    assert!(inventory.entry("GetEvalRun").is_none());
    assert!(inventory.entry("ListEvalRuns").is_none());
    assert!(inventory.entry("GetSampleObservation").is_some());
    assert!(inventory.entry("ClaimGatewayDispatch").is_some());
    assert!(inventory.entry("DecideGatewayExecution").is_some());
    assert!(inventory.entry("PutEvaluationPlan").is_some());
    assert!(inventory.entry("ResolveEvaluationPlan").is_some());
    assert!(inventory.entry("ExecuteEvaluationManifest").is_some());
    assert!(inventory.entry("GetEvaluationExecution").is_none());
    assert!(inventory.entry("CancelEvaluationExecution").is_some());
    assert!(inventory.entry("PutEvaluatorDefinition").is_some());
    assert!(inventory.entry("Chat").is_none());
    assert!(inventory.remaining_surfaces.is_empty());
    for surface in [
        "chisei.budget",
        "chisei.execution",
        "chisei.policy",
        "chisei.evaluation",
        "chisei.portfolio",
        "chisei.approvals",
        "chisei.learning",
        "chisei.observations",
        "gateway.governance",
    ] {
        assert!(
            inventory
                .complete_chisei_surfaces
                .iter()
                .any(|item| item == surface),
            "missing complete surface {surface}"
        );
    }
    for path in inventory.all_evidence_paths() {
        assert!(
            std::path::Path::new(path).exists(),
            "missing evidence path {path}"
        );
    }
}

#[test]
fn complete_chisei_capabilities_are_not_community_complete() {
    let complete = postgres_complete_chisei_capabilities().unwrap();
    assert!(
        complete
            .validate_required(COMMUNITY_REQUIRED_SURFACES)
            .is_err()
    );
    for surface in [
        "chisei.budget",
        "chisei.execution",
        "chisei.policy",
        "gateway.governance",
    ] {
        assert!(
            complete
                .reusable_surfaces
                .iter()
                .any(|item| item == surface),
            "missing proven surface {surface}"
        );
    }
}

#[test]
fn complete_chisei_capabilities_match_fixture() {
    let complete = postgres_complete_chisei_capabilities().unwrap();
    let fixture: sekai_chisei::runtime_backend::BackendCapabilities = serde_json::from_str(
        include_str!("fixtures/runtime_backend/postgres-chisei-complete-v1.json"),
    )
    .unwrap();
    assert_eq!(complete, fixture);
}
