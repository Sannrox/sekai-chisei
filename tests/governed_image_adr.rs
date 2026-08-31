//! ADR 0050 index and related-pointer checks for Issue #696.

const ADR_0039: &str = include_str!("../docs/decisions/0039-governed-documents.md");
const ADR_0050: &str = include_str!("../docs/decisions/0050-governed-images.md");
const DECISIONS_INDEX: &str = include_str!("../docs/decisions/README.md");
const IMAGES: &str = include_str!("../docs/images.md");
const DOCS_INDEX: &str = include_str!("../docs/README.md");
const REFERENCE: &str = include_str!("../docs/reference.md");
const POSTGRES_PARITY: &str = include_str!("../docs/postgres-sekai-parity.md");
const CHANGELOG: &str = include_str!("../CHANGELOG.md");

#[test]
fn adr_0050_is_indexed_and_names_governed_images() {
    assert!(
        DECISIONS_INDEX.contains(
            "[ADR 0050: Govern image assets with digest-bound renditions and annotations](0050-governed-images.md)"
        ),
        "decisions index must link ADR 0050"
    );
    assert!(ADR_0050.contains("#696"), "ADR 0050 must name Issue #696");
    assert!(
        ADR_0050.contains("discussions/798"),
        "ADR 0050 must point at Discussion 798"
    );
    assert!(
        ADR_0050.contains("sekai.governed-image/v1"),
        "ADR 0050 must name the image contract"
    );
}

#[test]
fn prior_adrs_point_at_governed_images_without_rewriting_history() {
    assert!(
        ADR_0039.contains("ADR 0050"),
        "ADR 0039 must record images in ADR 0050"
    );
    assert!(
        !ADR_0039.contains("Superseded by: ADR 0050"),
        "governed images must not supersede governed documents"
    );
}

#[test]
fn maintained_docs_point_at_the_governed_image_contract() {
    assert!(
        IMAGES.contains("sekaictl admin images"),
        "operator page must document the images CLI"
    );
    assert!(
        IMAGES.contains("discussions/798"),
        "operator page must point at Discussion 798"
    );
    assert!(
        IMAGES.contains("sekai.governed-image/v1"),
        "operator page must name the image contract"
    );
    assert!(
        DOCS_INDEX.contains("images.md"),
        "docs index must link governed images"
    );
    assert!(
        REFERENCE.contains("images.md"),
        "reference index must link governed images"
    );
    assert!(
        POSTGRES_PARITY.contains("sekai.governed-image/v1"),
        "postgres parity must list governed images"
    );
    assert!(
        POSTGRES_PARITY.contains("0050-governed-images.md"),
        "postgres parity must point at ADR 0050"
    );
    assert!(
        CHANGELOG.contains("sekai.governed-image/v1"),
        "changelog must record governed images"
    );
}
