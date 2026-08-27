//! ADR 0038 index and related-pointer checks for Issue #687.

const ADR_0027: &str = include_str!("../docs/decisions/0027-explicit-property-grants.md");
const ADR_0030: &str = include_str!("../docs/decisions/0030-row-scoped-query-access.md");
const ADR_0038: &str = include_str!("../docs/decisions/0038-property-level-reads.md");
const DECISIONS_INDEX: &str = include_str!("../docs/decisions/README.md");
const OBJECT_SECURITY: &str = include_str!("../docs/object-security.md");
const ARCHITECTURE: &str = include_str!("../docs/architecture.md");

#[test]
fn adr_0038_is_indexed_and_names_property_level_reads() {
    assert!(
        DECISIONS_INDEX.contains(
            "[ADR 0038: Authorize property-level reads before every public query surface](0038-property-level-reads.md)"
        ),
        "decisions index must link ADR 0038"
    );
    assert!(ADR_0038.contains("#687"), "ADR 0038 must name Issue #687");
    assert!(
        ADR_0038.contains("before count"),
        "ADR 0038 must authorize named property predicates before query materialization"
    );
}

#[test]
fn prior_adrs_point_at_property_level_reads_without_rewriting_history() {
    assert!(
        ADR_0027.contains("ADR 0038"),
        "ADR 0027 must point at cross-surface property-level reads"
    );
    assert!(
        ADR_0030.contains("ADR 0038"),
        "ADR 0030 must point at property-level reads"
    );
    assert!(
        !ADR_0027.contains("Superseded by: ADR 0038"),
        "property-level reads must not supersede explicit property grants"
    );
}

#[test]
fn maintained_docs_point_at_property_level_read_contract() {
    assert!(
        OBJECT_SECURITY.contains("Every public query operator"),
        "object-security guide must document deny-before-query property reads"
    );
    assert!(
        ARCHITECTURE.contains("0038-property-level-reads.md"),
        "architecture must point at ADR 0038"
    );
}
