//! ADR 0087 index and advisory-until-shipped checks for Issue #1089.

const ADR_0018: &str = include_str!("../docs/decisions/0018-ontology-relation-cardinality.md");
const ADR_0087: &str =
    include_str!("../docs/decisions/0087-enforce-relation-cardinality-maximum.md");
const DECISIONS_INDEX: &str = include_str!("../docs/decisions/README.md");
const OPERATOR: &str = include_str!("../docs/ontology.md");

#[test]
fn adr_0087_is_indexed_and_supersedes_only_the_maximum() {
    assert!(DECISIONS_INDEX.contains(
        "[ADR 0087: Enforce ontology relation maximum cardinality; keep the minimum advisory](0087-enforce-relation-cardinality-maximum.md)"
    ));
    assert!(ADR_0087.contains("#1089"));
    assert!(ADR_0087.contains("relation_cardinality_exceeded"));
    assert!(ADR_0087.contains("Count distinct target objects per"));
    assert!(ADR_0018.contains("for the maximum bound only, enforced since #1132"));
}

#[test]
fn operator_page_states_the_enforced_maximum_and_advisory_minimum() {
    assert!(OPERATOR.contains("relation_cardinality_exceeded"));
    assert!(OPERATOR.contains("The minimum stays advisory metadata"));
}
