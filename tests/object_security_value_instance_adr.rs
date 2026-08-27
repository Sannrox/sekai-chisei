//! ADR 0049 index and related-pointer checks for Issue #695.

const ADR_0027: &str = include_str!("../docs/decisions/0027-explicit-property-grants.md");
const ADR_0030: &str = include_str!("../docs/decisions/0030-row-scoped-query-access.md");
const ADR_0038: &str = include_str!("../docs/decisions/0038-property-level-reads.md");
const ADR_0049: &str = include_str!("../docs/decisions/0049-value-instance-access.md");
const DECISIONS_INDEX: &str = include_str!("../docs/decisions/README.md");
const OBJECT_SECURITY: &str = include_str!("../docs/object-security.md");
const ARCHITECTURE: &str = include_str!("../docs/architecture.md");

#[test]
fn adr_0049_is_indexed_and_names_value_instance_access() {
    assert!(
        DECISIONS_INDEX.contains(
            "[ADR 0049: Enforce value-instance access as a cell grant](0049-value-instance-access.md)"
        ),
        "decisions index must link ADR 0049"
    );
    assert!(ADR_0049.contains("#695"), "ADR 0049 must name Issue #695");
    assert!(
        ADR_0049.contains("before the value is examined"),
        "ADR 0049 must authorize named cells before query materialization"
    );
}

#[test]
fn prior_adrs_point_at_value_instance_access_without_rewriting_history() {
    assert!(
        ADR_0027.contains("ADR 0049"),
        "ADR 0027 must point at value-instance access"
    );
    assert!(
        ADR_0030.contains("ADR 0049"),
        "ADR 0030 must point at value-instance access"
    );
    assert!(
        ADR_0038.contains("ADR 0049"),
        "ADR 0038 must point at value-instance access"
    );
    assert!(
        !ADR_0027.contains("Superseded by: ADR 0049"),
        "value-instance access must not supersede explicit property grants"
    );
    assert!(
        !ADR_0038.contains("Superseded by: ADR 0049"),
        "value-instance access must not supersede property-level reads"
    );
}

#[test]
fn maintained_docs_point_at_value_instance_access_contract() {
    assert!(
        OBJECT_SECURITY.contains("value_instance_grants"),
        "object-security guide must document cell grants"
    );
    assert!(
        OBJECT_SECURITY.contains("Hidden and unknown cells"),
        "object-security guide must document hidden/unknown cell equivalence"
    );
    assert!(
        !OBJECT_SECURITY.contains("Value-instance grants remain a later issue"),
        "object-security guide must not defer cell grants"
    );
    assert!(
        ARCHITECTURE.contains("0049-value-instance-access.md"),
        "architecture must point at ADR 0049"
    );
}
