//! ADR 0059 index and related-pointer checks for Issue #715.

const ADR_0059: &str = include_str!("../docs/decisions/0059-autonomous-envelopes.md");
const DECISIONS_INDEX: &str = include_str!("../docs/decisions/README.md");
const OPERATOR: &str = include_str!("../docs/autonomous-envelopes.md");

#[test]
fn adr_0059_is_indexed_and_names_autonomous_envelopes() {
    assert!(
        DECISIONS_INDEX.contains(
            "[ADR 0059: Admit autonomous actions only inside a signed current envelope](0059-autonomous-envelopes.md)"
        ),
        "decisions index must link ADR 0059"
    );
    assert!(ADR_0059.contains("#715"), "ADR 0059 must name Issue #715");
    assert!(
        ADR_0059.contains("sekai.autonomous-envelope/v1"),
        "ADR 0059 must name the autonomous envelope contract"
    );
}

#[test]
fn operator_page_documents_the_autonomy_cli() {
    assert!(
        OPERATOR.contains("sekaictl admin autonomy"),
        "operator page must document the autonomy CLI"
    );
}
