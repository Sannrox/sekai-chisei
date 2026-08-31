//! ADR 0052 index and related-pointer checks for Issue #707.

const ADR_0051: &str = include_str!("../docs/decisions/0051-versioned-client-packages.md");
const ADR_0052: &str = include_str!("../docs/decisions/0052-capability-package-certification.md");
const DECISIONS_INDEX: &str = include_str!("../docs/decisions/README.md");
const OPERATOR: &str = include_str!("../docs/capability-packages.md");

#[test]
fn adr_0052_is_indexed_and_names_capability_packages() {
    assert!(
        DECISIONS_INDEX.contains(
            "[ADR 0052: Certify capability packages against an immutable digest](0052-capability-package-certification.md)"
        ),
        "decisions index must link ADR 0052"
    );
    assert!(ADR_0052.contains("#707"), "ADR 0052 must name Issue #707");
    assert!(
        ADR_0052.contains("sekai.capability-package-certification/v1"),
        "ADR 0052 must name the certification contract"
    );
    assert!(
        ADR_0051.contains("sekai.client-package/v1"),
        "related client-package ADR must remain distinct"
    );
}

#[test]
fn operator_page_documents_the_packages_cli() {
    assert!(
        OPERATOR.contains("sekaictl admin packages"),
        "operator page must document the packages CLI"
    );
    assert!(
        OPERATOR.contains("sekai.capability-package-certification/v1"),
        "operator page must name the certification contract"
    );
}
