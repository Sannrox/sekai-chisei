//! ADR 0067 index checks for Issue #837.

const ADR_0067: &str = include_str!("../docs/decisions/0067-definition-consumer-impact.md");
const DECISIONS_INDEX: &str = include_str!("../docs/decisions/README.md");
const OPERATOR: &str = include_str!("../docs/definition-consumer-impact.md");

#[test]
fn adr_0067_is_indexed_and_names_registered_declarations() {
    assert!(DECISIONS_INDEX.contains(
        "[ADR 0067: Report consumer impact from registered declarations only](0067-definition-consumer-impact.md)"
    ));
    assert!(ADR_0067.contains("#837"));
    assert!(ADR_0067.contains("sekai.definition-consumer-binding/v1"));
    assert!(ADR_0067.contains("ReportDefinitionConsumerImpact"));
}

#[test]
fn operator_page_keeps_zero_visible_from_proving_zero_impact() {
    assert!(OPERATOR.contains("Zero visible dependents is not proof of zero impact"));
}
