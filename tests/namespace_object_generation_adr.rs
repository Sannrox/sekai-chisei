//! ADR 0104 index and cache-key checks for Issue #1492.

const ADR_0104: &str = include_str!("../docs/decisions/0104-namespace-object-change-generation.md");
const DECISIONS_INDEX: &str = include_str!("../docs/decisions/README.md");
const CHANGELOG: &str = include_str!("../CHANGELOG.md");

#[test]
fn adr_0104_is_indexed_and_names_the_generation_table() {
    assert!(
        DECISIONS_INDEX.contains(
            "[ADR 0104: Per-namespace object change generation keys the privacy scan cache](0104-namespace-object-change-generation.md)"
        ),
        "decisions index must link ADR 0104"
    );
    assert!(ADR_0104.contains("#1492"), "ADR 0104 must name Issue #1492");
    assert!(
        ADR_0104.contains("sekai_namespace_object_generation"),
        "ADR 0104 must name the generation table"
    );
    assert!(
        CHANGELOG.contains("0059_namespace_object_generation"),
        "changelog must name the PostgreSQL migration"
    );
}
