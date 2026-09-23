//! ADR 0090 index and operator-page checks for Issue #1092.

const ADR_0090: &str = include_str!("../docs/decisions/0090-object-change-action-bindings.md");
const DECISIONS_INDEX: &str = include_str!("../docs/decisions/README.md");
const OPERATOR: &str = include_str!("../docs/object-change-subscriptions.md");

#[test]
fn adr_0090_is_indexed_and_names_the_binding_contract() {
    assert!(DECISIONS_INDEX.contains(
        "[ADR 0090: Bind object changes to governed Actions through a plane-owned binding](0090-object-change-action-bindings.md)"
    ));
    assert!(ADR_0090.contains("#1092"));
    assert!(ADR_0090.contains("sekai.action-binding/v1"));
    assert!(ADR_0090.contains("parameter_source_unavailable"));
}

#[test]
fn operator_page_keeps_hidden_fields_out_of_parameters() {
    assert!(OPERATOR.contains("hidden fields never become parameters"));
    assert!(OPERATOR.contains("RunActionBinding"));
}
