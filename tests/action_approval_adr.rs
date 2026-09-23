//! ADR 0089 index and operator-page checks for Issue #1084.

const ADR_0089: &str = include_str!("../docs/decisions/0089-park-and-decide-action-instances.md");
const DECISIONS_INDEX: &str = include_str!("../docs/decisions/README.md");
const OPERATOR: &str = include_str!("../docs/governed-action-instances.md");

#[test]
fn adr_0089_is_indexed_and_names_the_decide_rpc() {
    assert!(DECISIONS_INDEX.contains(
        "[ADR 0089: Park approval-gated Action instances and decide them explicitly](0089-park-and-decide-action-instances.md)"
    ));
    assert!(ADR_0089.contains("#1084"));
    assert!(ADR_0089.contains("DecideActionInstance"));
    assert!(ADR_0089.contains("The submitter never decides their own instance"));
}

#[test]
fn operator_page_documents_parking_and_the_stale_fence() {
    assert!(OPERATOR.contains("`status=parked`"));
    assert!(OPERATOR.contains("stale_on_resume"));
    assert!(OPERATOR.contains("access denied"));
}
