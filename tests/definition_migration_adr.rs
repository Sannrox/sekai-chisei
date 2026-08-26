//! ADR 0028 index and related-pointer checks for Issue #693.

const ADR_0024: &str = include_str!("../docs/decisions/0024-governed-definition-branches.md");
const ADR_0028: &str = include_str!("../docs/decisions/0028-checkpointed-fact-migration.md");
const DECISIONS_INDEX: &str = include_str!("../docs/decisions/README.md");
const BRANCHES: &str = include_str!("../docs/definition-branches.md");

#[test]
fn adr_0028_is_indexed_and_names_checkpointed_migration() {
    assert!(DECISIONS_INDEX.contains(
        "[ADR 0028: Execute approved checkpointed fact migration](0028-checkpointed-fact-migration.md)"
    ));
    assert!(ADR_0028.contains("#693"));
    assert!(ADR_0028.contains("dry-run") && ADR_0028.contains("rollback"));
    assert!(
        ADR_0028.contains("never rewrite")
            || ADR_0028.contains("never rewritten")
            || ADR_0028.contains("never rewritten")
            || ADR_0028.contains("Published definition rows are never rewritten")
    );
}

#[test]
fn adr_0024_points_at_fact_migration_without_rewriting_history() {
    assert!(ADR_0024.contains("ADR 0028"));
    assert!(!ADR_0024.contains("Superseded by: ADR 0028"));
}

#[test]
fn definition_branch_guide_names_execute_rpc() {
    assert!(BRANCHES.contains("ExecuteDefinitionFactMigration"));
    assert!(BRANCHES.contains("0028-checkpointed-fact-migration.md"));
}
