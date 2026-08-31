//! ADR 0051 index and related-pointer checks for Issue #702.

const ADR_0016: &str = include_str!("../docs/decisions/0016-versioned-rust-core-loop-client.md");
const ADR_0051: &str = include_str!("../docs/decisions/0051-versioned-client-packages.md");
const DECISIONS_INDEX: &str = include_str!("../docs/decisions/README.md");
const SDK_PACKAGES: &str = include_str!("../docs/sdk-packages.md");
const DOCS_INDEX: &str = include_str!("../docs/README.md");
const REFERENCE: &str = include_str!("../docs/reference.md");
const POSTGRES_PARITY: &str = include_str!("../docs/postgres-sekai-parity.md");
const CHANGELOG: &str = include_str!("../CHANGELOG.md");

#[test]
fn adr_0051_is_indexed_and_names_client_packages() {
    assert!(
        DECISIONS_INDEX.contains(
            "[ADR 0051: Publish versioned client packages with protocol and provenance pins](0051-versioned-client-packages.md)"
        ),
        "decisions index must link ADR 0051"
    );
    assert!(ADR_0051.contains("#702"), "ADR 0051 must name Issue #702");
    assert!(
        ADR_0051.contains("discussions/804"),
        "ADR 0051 must point at Discussion 804"
    );
    assert!(
        ADR_0051.contains("sekai.client-package/v1"),
        "ADR 0051 must name the client-package contract"
    );
}

#[test]
fn prior_adrs_remain_distinct_from_client_package_publication() {
    assert!(
        ADR_0016.contains("sekai-client"),
        "ADR 0016 must keep the Rust client crate"
    );
    assert!(
        !ADR_0016.contains("Superseded by: ADR 0051"),
        "client-package publication must not supersede the Rust client crate"
    );
}

#[test]
fn maintained_docs_point_at_the_client_package_contract() {
    assert!(
        SDK_PACKAGES.contains("sekaictl admin sdk-packages"),
        "operator page must document the sdk-packages CLI"
    );
    assert!(
        SDK_PACKAGES.contains("discussions/804"),
        "operator page must point at Discussion 804"
    );
    assert!(
        SDK_PACKAGES.contains("sekai.client-package/v1"),
        "operator page must name the client-package contract"
    );
    assert!(
        DOCS_INDEX.contains("sdk-packages.md"),
        "docs index must link client packages"
    );
    assert!(
        REFERENCE.contains("sdk-packages.md"),
        "reference index must link client packages"
    );
    assert!(
        POSTGRES_PARITY.contains("sekai.client-package/v1"),
        "postgres parity must list client packages"
    );
    assert!(
        POSTGRES_PARITY.contains("0051-versioned-client-packages.md"),
        "postgres parity must point at ADR 0051"
    );
    assert!(
        CHANGELOG.contains("sekai.client-package/v1"),
        "changelog must record client packages"
    );
}
