//! ADR 0107 index and contract checks for Issue #1396.

const ADR_0107: &str = include_str!("../docs/decisions/0107-model-release-evidence.md");
const DECISIONS_INDEX: &str = include_str!("../docs/decisions/README.md");
const CHANGELOG: &str = include_str!("../CHANGELOG.md");

#[test]
fn adr_0107_is_indexed_and_names_the_evidence_tables() {
    assert!(
        DECISIONS_INDEX.contains(
            "[ADR 0107: Two-way model-release evidence for opt-in hosted routes](0107-model-release-evidence.md)"
        ),
        "decisions index must link ADR 0107"
    );
    assert!(ADR_0107.contains("#1396"), "ADR 0107 must name Issue #1396");
    assert!(
        ADR_0107.contains("chisei_model_release_"),
        "ADR 0107 must name the evidence tables"
    );
    assert!(
        CHANGELOG.contains("0063_chisei_model_release_evidence"),
        "changelog must name the PostgreSQL migration"
    );
    assert!(
        CHANGELOG.contains("GATE:mig"),
        "changelog must mark GATE:mig"
    );
}
