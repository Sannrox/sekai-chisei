//! ADR 0069 index and carrier-name checks for Issue #886.

const ADR_0069: &str = include_str!("../docs/decisions/0069-operation-correlation.md");
const DECISIONS_INDEX: &str = include_str!("../docs/decisions/README.md");
const OPERATOR: &str = include_str!("../docs/operation-correlation.md");

#[test]
fn adr_0069_is_indexed_and_names_the_carriers() {
    assert!(
        DECISIONS_INDEX.contains(
            "[ADR 0069: Stamp one caller operation identity on spans, receipts, and object changes](0069-operation-correlation.md)"
        ),
        "decisions index must link ADR 0069"
    );
    assert!(ADR_0069.contains("#886"), "ADR 0069 must name Issue #886");
    assert!(
        ADR_0069.contains("x-sekai-operation-id"),
        "ADR 0069 must name the header"
    );
}

#[test]
fn operator_page_names_the_four_wire_fields() {
    assert!(OPERATOR.contains("x-sekai-operation-id"));
    assert!(OPERATOR.contains("sekai.operation_id"));
    assert!(OPERATOR.contains("OperationReceipt.operation_id"));
    assert!(OPERATOR.contains("ObjectChangeEvent.operation_id"));
}
