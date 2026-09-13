//! ADR 0054 index and related-pointer checks for Issue #709.

const ADR_0054: &str = include_str!("../docs/decisions/0054-workflow-action-bridge.md");
const ADR_0065: &str = include_str!("../docs/decisions/0065-workflow-action-postgres-parity.md");
const DECISIONS_INDEX: &str = include_str!("../docs/decisions/README.md");
const OPERATOR: &str = include_str!("../docs/workflow-actions.md");

#[test]
fn adr_0054_is_indexed_and_names_the_workflow_bridge() {
    assert!(
        DECISIONS_INDEX.contains(
            "[ADR 0054: Map workflow steps through ActionInstance admission](0054-workflow-action-bridge.md)"
        ),
        "decisions index must link ADR 0054"
    );
    assert!(ADR_0054.contains("#709"), "ADR 0054 must name Issue #709");
    assert!(
        ADR_0054.contains("sekai.workflow-action-bridge/v1"),
        "ADR 0054 must name the workflow-action contract"
    );
    assert!(
        DECISIONS_INDEX.contains(
            "[ADR 0065: Persist workflow bindings and callbacks on PostgreSQL without a second admission plane](0065-workflow-action-postgres-parity.md)"
        ),
        "decisions index must link ADR 0065"
    );
    assert!(
        ADR_0065.contains("issues/823"),
        "ADR 0065 must name Issue #823"
    );
    assert!(
        ADR_0065.contains("commit_workflow_transition"),
        "ADR 0065 must keep the existing transition as the only write"
    );
}

#[test]
fn operator_page_documents_the_workflow_cli() {
    assert!(
        OPERATOR.contains("sekaictl admin workflow"),
        "operator page must document the workflow CLI"
    );
}
