//! ADR 0058 index and related-pointer checks for Issue #713.

const ADR_0058: &str = include_str!("../docs/decisions/0058-model-platform-certification.md");
const DECISIONS_INDEX: &str = include_str!("../docs/decisions/README.md");
const OPERATOR: &str = include_str!("../docs/model-platform-certification.md");

#[test]
fn adr_0058_is_indexed_and_names_model_platform_certification() {
    assert!(
        DECISIONS_INDEX.contains(
            "[ADR 0058: Certify model-platform adapters against evaluation evidence](0058-model-platform-certification.md)"
        ),
        "decisions index must link ADR 0058"
    );
    assert!(ADR_0058.contains("#713"), "ADR 0058 must name Issue #713");
    assert!(
        ADR_0058.contains("sekai.model-platform-certification/v1"),
        "ADR 0058 must name the model-platform certification contract"
    );
    assert!(
        ADR_0058.contains("sekai.evaluation-evidence/v1"),
        "ADR 0058 must pin evaluation evidence"
    );
}

#[test]
fn operator_page_documents_the_providers_cli() {
    assert!(
        OPERATOR.contains("sekaictl admin providers"),
        "operator page must document the providers CLI"
    );
}
