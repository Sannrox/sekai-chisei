//! ADR 0056 index and related-pointer checks for Issue #711.

const ADR_0056: &str = include_str!("../docs/decisions/0056-warehouse-projections.md");
const DECISIONS_INDEX: &str = include_str!("../docs/decisions/README.md");
const OPERATOR: &str = include_str!("../docs/warehouse-projections.md");

#[test]
fn adr_0056_is_indexed_and_names_warehouse_projections() {
    assert!(
        DECISIONS_INDEX.contains(
            "[ADR 0056: Export warehouse projections with security-metadata pins](0056-warehouse-projections.md)"
        ),
        "decisions index must link ADR 0056"
    );
    assert!(ADR_0056.contains("#711"), "ADR 0056 must name Issue #711");
    assert!(
        ADR_0056.contains("sekai.warehouse-projection/v1"),
        "ADR 0056 must name the warehouse projection contract"
    );
}

#[test]
fn operator_page_documents_the_warehouse_cli() {
    assert!(
        OPERATOR.contains("sekaictl admin warehouse"),
        "operator page must document the warehouse CLI"
    );
}
