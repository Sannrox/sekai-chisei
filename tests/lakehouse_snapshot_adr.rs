//! ADR 0057 index and related-pointer checks for Issue #712.

const ADR_0057: &str = include_str!("../docs/decisions/0057-lakehouse-snapshots.md");
const DECISIONS_INDEX: &str = include_str!("../docs/decisions/README.md");
const OPERATOR: &str = include_str!("../docs/lakehouse-snapshots.md");

#[test]
fn adr_0057_is_indexed_and_names_lakehouse_snapshots() {
    assert!(
        DECISIONS_INDEX.contains(
            "[ADR 0057: Export partitioned lakehouse snapshots with schema evolution](0057-lakehouse-snapshots.md)"
        ),
        "decisions index must link ADR 0057"
    );
    assert!(ADR_0057.contains("#712"), "ADR 0057 must name Issue #712");
    assert!(
        ADR_0057.contains("sekai.lakehouse-snapshot/v1"),
        "ADR 0057 must name the lakehouse snapshot contract"
    );
}

#[test]
fn operator_page_documents_the_lakehouse_cli() {
    assert!(
        OPERATOR.contains("sekaictl admin lakehouse"),
        "operator page must document the lakehouse CLI"
    );
}
