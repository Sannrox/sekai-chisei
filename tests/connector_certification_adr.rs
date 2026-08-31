//! ADR 0055 index and related-pointer checks for Issue #710.

const ADR_0055: &str = include_str!("../docs/decisions/0055-connector-certification.md");
const DECISIONS_INDEX: &str = include_str!("../docs/decisions/README.md");
const OPERATOR: &str = include_str!("../docs/connector-certification.md");

#[test]
fn adr_0055_is_indexed_and_names_connector_certification() {
    assert!(
        DECISIONS_INDEX.contains(
            "[ADR 0055: Certify connectors against an immutable digest](0055-connector-certification.md)"
        ),
        "decisions index must link ADR 0055"
    );
    assert!(ADR_0055.contains("#710"), "ADR 0055 must name Issue #710");
    assert!(
        ADR_0055.contains("sekai.connector-certification/v1"),
        "ADR 0055 must name the connector certification contract"
    );
}

#[test]
fn operator_page_documents_the_connectors_cli() {
    assert!(
        OPERATOR.contains("sekaictl admin connectors"),
        "operator page must document the connectors CLI"
    );
}
