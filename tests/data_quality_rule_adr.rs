//! ADR 0045 index and related-pointer checks for Issue #681.

const ADR_0011: &str =
    include_str!("../docs/decisions/0011-separate-invariant-facts-and-evaluation-plans.md");
const ADR_0045: &str = include_str!("../docs/decisions/0045-governed-data-quality-rules.md");
const DECISIONS_INDEX: &str = include_str!("../docs/decisions/README.md");
const OPERATOR: &str = include_str!("../docs/data-quality-rules.md");

#[test]
fn adr_0045_is_indexed_and_names_data_quality_rules() {
    assert!(
        DECISIONS_INDEX.contains(
            "[ADR 0045: Evaluate versioned data-quality rules as content-bound results](0045-governed-data-quality-rules.md)"
        ),
        "decisions index must link ADR 0045"
    );
    assert!(ADR_0045.contains("#681"), "ADR 0045 must name Issue #681");
    assert!(
        ADR_0045.contains("become `pass`"),
        "ADR 0045 must keep non-pass states distinct from success"
    );
    assert!(
        ADR_0011.contains("evaluation"),
        "related evaluation ADR must remain the plan/fact boundary"
    );
}

#[test]
fn operator_page_documents_the_quality_cli() {
    assert!(
        OPERATOR.contains("sekaictl admin quality"),
        "operator page must document the quality CLI"
    );
    assert!(
        OPERATOR.contains("chisei.data-quality-result/v1"),
        "operator page must name the result contract"
    );
}
