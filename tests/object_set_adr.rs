//! ADR 0066 index and related-pointer checks for Issue #835, and ADR 0086
//! evaluate-once checks for Issue #1088.

const ADR_0066: &str = include_str!("../docs/decisions/0066-object-set-evaluate.md");
const ADR_0086: &str = include_str!("../docs/decisions/0086-object-set-is-its-descriptor.md");
const DECISIONS_INDEX: &str = include_str!("../docs/decisions/README.md");
const OPERATOR: &str = include_str!("../docs/object-set.md");

#[test]
fn adr_0066_is_indexed_and_names_object_set_evaluate() {
    assert!(
        DECISIONS_INDEX.contains(
            "[ADR 0066: Evaluate revision-bound ObjectSet descriptors without a query language](0066-object-set-evaluate.md)"
        ),
        "decisions index must link ADR 0066"
    );
    assert!(ADR_0066.contains("#835"), "ADR 0066 must name Issue #835");
    assert!(
        ADR_0066.contains("sekai.object-set/v1"),
        "ADR 0066 must name the ObjectSet contract"
    );
    assert!(
        ADR_0066.contains("EvaluateObjectSet"),
        "ADR 0066 must keep EvaluateObjectSet as the only evaluate RPC"
    );
}

#[test]
fn operator_page_documents_non_authority() {
    assert!(
        OPERATOR.contains("EvaluateObjectSetResponse.authority"),
        "operator page must keep the descriptor from granting authority"
    );
}

#[test]
fn adr_0086_keeps_evaluate_once_and_stores_no_members() {
    assert!(
        DECISIONS_INDEX.contains(
            "[ADR 0086: An ObjectSet is its descriptor; members are not stored](0086-object-set-is-its-descriptor.md)"
        ),
        "decisions index must link ADR 0086"
    );
    assert!(ADR_0086.contains("#1088"), "ADR 0086 must name Issue #1088");
    assert!(
        ADR_0086.contains("Evaluate-once remains the 1.x contract"),
        "ADR 0086 must state the 1.x contract"
    );
    assert!(
        OPERATOR.contains("The server keeps no ObjectSet"),
        "operator page must not imply a saved set"
    );
    assert!(
        OPERATOR.contains("the durable form of a set"),
        "operator page must name the descriptor as the durable form"
    );
}
