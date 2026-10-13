//! ADR 0106 index and contract checks for Issue #1493.

const ADR_0106: &str = include_str!("../docs/decisions/0106-namespace-model-review-state.md");
const DECISIONS_INDEX: &str = include_str!("../docs/decisions/README.md");
const CHANGELOG: &str = include_str!("../CHANGELOG.md");

#[test]
fn adr_0106_is_indexed_and_names_the_review_tables() {
    assert!(
        DECISIONS_INDEX.contains(
            "[ADR 0106: Namespace-scoped model review state and family enablement](0106-namespace-model-review-state.md)"
        ),
        "decisions index must link ADR 0106"
    );
    assert!(ADR_0106.contains("#1493"), "ADR 0106 must name Issue #1493");
    assert!(
        ADR_0106.contains("chisei_model_review"),
        "ADR 0106 must name the model review table"
    );
    assert!(
        ADR_0106.contains("chisei_model_family_enablement"),
        "ADR 0106 must name the family enablement table"
    );
    assert!(
        CHANGELOG.contains("0061_chisei_model_review"),
        "changelog must name the PostgreSQL migration"
    );
}
