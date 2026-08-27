//! ADR 0044 index and related-pointer checks for Issue #680.

const ADR_0027: &str = include_str!("../docs/decisions/0027-explicit-property-grants.md");
const ADR_0030: &str = include_str!("../docs/decisions/0030-row-scoped-query-access.md");
const ADR_0038: &str = include_str!("../docs/decisions/0038-property-level-reads.md");
const ADR_0044: &str = include_str!("../docs/decisions/0044-governed-geospatial-queries.md");
const DECISIONS_INDEX: &str = include_str!("../docs/decisions/README.md");
const OBJECT_SECURITY: &str = include_str!("../docs/object-security.md");
const ARCHITECTURE: &str = include_str!("../docs/architecture.md");
const GEOSPATIAL: &str = include_str!("../docs/geospatial-queries.md");

#[test]
fn adr_0044_is_indexed_and_names_governed_geospatial_queries() {
    assert!(
        DECISIONS_INDEX.contains(
            "[ADR 0044: Query governed geospatial properties after property authorization](0044-governed-geospatial-queries.md)"
        ),
        "decisions index must link ADR 0044"
    );
    assert!(ADR_0044.contains("#680"), "ADR 0044 must name Issue #680");
    assert!(
        ADR_0044.contains("before count"),
        "ADR 0044 must authorize the named property before query materialization"
    );
}

#[test]
fn prior_adrs_point_at_geospatial_queries_without_rewriting_history() {
    assert!(
        ADR_0027.contains("ADR 0044"),
        "ADR 0027 must point at governed geospatial queries"
    );
    assert!(
        ADR_0030.contains("ADR 0044"),
        "ADR 0030 must point at governed geospatial queries"
    );
    assert!(
        ADR_0038.contains("ADR 0044"),
        "ADR 0038 must point at governed geospatial queries"
    );
    assert!(
        !ADR_0027.contains("Superseded by: ADR 0044"),
        "geospatial queries must not supersede explicit property grants"
    );
}

#[test]
fn maintained_docs_point_at_the_geospatial_query_contract() {
    assert!(
        OBJECT_SECURITY.contains("sekai.geospatial-query/v1"),
        "object-security guide must document geospatial property authorization"
    );
    assert!(
        ARCHITECTURE.contains("0044-governed-geospatial-queries.md"),
        "architecture must point at ADR 0044"
    );
    assert!(
        GEOSPATIAL.contains("sekaictl admin geospatial query"),
        "operator page must document the geospatial CLI"
    );
}
