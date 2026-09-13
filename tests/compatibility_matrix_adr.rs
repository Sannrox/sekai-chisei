//! ADR 0070 index checks for Issue #873.

const ADR_0070: &str = include_str!("../docs/decisions/0070-compatibility-matrix.md");
const DECISIONS_INDEX: &str = include_str!("../docs/decisions/README.md");
const SDK_PACKAGES: &str = include_str!("../docs/sdk-packages.md");

#[test]
fn adr_0070_is_indexed_and_names_the_projection() {
    assert!(
        DECISIONS_INDEX.contains(
            "[ADR 0070: Publish a compatibility matrix as a projection of shipped metadata](0070-compatibility-matrix.md)"
        ),
        "decisions index must link ADR 0070"
    );
    assert!(ADR_0070.contains("#873"), "ADR 0070 must name Issue #873");
    assert!(
        ADR_0070.contains("sekai.compatibility-matrix/v1"),
        "ADR 0070 must name the matrix contract"
    );
}

#[test]
fn operator_page_documents_the_pin_check_and_upgrade_cadence() {
    assert!(
        SDK_PACKAGES.contains("sekaictl admin compatibility check"),
        "operator page must document the consumer pin check"
    );
    assert!(
        SDK_PACKAGES.contains("compatibility.json"),
        "operator page must name the matrix artifact"
    );
    assert!(
        SDK_PACKAGES.contains("Upgrade cadence"),
        "operator page must document consumer upgrade cadence"
    );
}
