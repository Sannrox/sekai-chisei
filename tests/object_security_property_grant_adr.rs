//! ADR 0027 index and related-pointer checks for Issue #676.

const ADR_0025: &str = include_str!("../docs/decisions/0025-storage-enforced-object-security.md");
const ADR_0027: &str = include_str!("../docs/decisions/0027-explicit-property-grants.md");
const DECISIONS_INDEX: &str = include_str!("../docs/decisions/README.md");
const OBJECT_SECURITY: &str = include_str!("../docs/object-security.md");
const ARCHITECTURE: &str = include_str!("../docs/architecture.md");

#[test]
fn adr_0027_is_indexed_and_names_explicit_property_grants() {
    assert!(
        DECISIONS_INDEX.contains(
            "[ADR 0027: Deny property access without an explicit grant](0027-explicit-property-grants.md)"
        ),
        "decisions index must link ADR 0027"
    );
    assert!(ADR_0027.contains("#676"), "ADR 0027 must name Issue #676");
    assert!(
        ADR_0027.contains("property_grants"),
        "ADR 0027 must name the property_grants field"
    );
    assert!(
        ADR_0027.contains("omit") && ADR_0027.contains("fail closed"),
        "ADR 0027 must record omission and fail-closed filters and writes"
    );
}

#[test]
fn adr_0025_points_at_property_grant_follow_up_without_rewriting_history() {
    assert!(
        ADR_0025.contains("ADR 0027"),
        "ADR 0025 must point at explicit property grants"
    );
    assert!(
        !ADR_0025.contains("Superseded by: ADR 0027"),
        "property grants must not supersede object-level storage enforcement"
    );
}

#[test]
fn maintained_docs_point_at_property_grant_contract() {
    assert!(
        OBJECT_SECURITY.contains("property_grants"),
        "object-security guide must document property grants"
    );
    assert!(
        OBJECT_SECURITY.contains("never fetched for client-side masking"),
        "hidden properties must not be fetched for client-side masking"
    );
    assert!(
        ARCHITECTURE.contains("0027-explicit-property-grants.md"),
        "architecture must point at ADR 0027"
    );
}
