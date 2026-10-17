//! ADR 0112 index and operator-boundary checks for Issue #1552.

const ADR_0112: &str = include_str!("../docs/decisions/0112-namespaced-object-log-identity.md");
const ADR_0091: &str = include_str!("../docs/decisions/0091-object-log-owns-evaluate-identity.md");
const DECISIONS_INDEX: &str = include_str!("../docs/decisions/README.md");
const OPERATOR: &str = include_str!("../docs/object-type-index.md");

#[test]
fn adr_0112_is_indexed_and_amends_0091() {
    assert!(DECISIONS_INDEX.contains(
        "[ADR 0112: Plane namespace is part of object-log identity](0112-namespaced-object-log-identity.md)"
    ));
    assert!(ADR_0112.contains("#1552"));
    assert!(ADR_0112.contains("migrate-object-log"));
    assert!(ADR_0091.contains("[ADR 0112](0112-namespaced-object-log-identity.md)"));
}

#[test]
fn operator_page_names_the_projection_migration() {
    assert!(OPERATOR.contains("sekaictl admin store migrate-object-log"));
    assert!(OPERATOR.contains("(namespace, kind, key)"));
}
