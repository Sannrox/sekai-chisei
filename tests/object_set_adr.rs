//! ADR 0066 index and related-pointer checks for Issue #835.

const ADR_0066: &str = include_str!("../docs/decisions/0066-object-set-evaluate.md");
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
