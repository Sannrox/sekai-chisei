//! ADR 0026 index and related-pointer checks for Issue #734.

const ADR_0024: &str = include_str!("../docs/decisions/0024-governed-definition-branches.md");
const ADR_0026: &str = include_str!("../docs/decisions/0026-governed-branch-proposals.md");
const DECISIONS_INDEX: &str = include_str!("../docs/decisions/README.md");
const DEFINITION_BRANCHES: &str = include_str!("../docs/definition-branches.md");
const ARCHITECTURE: &str = include_str!("../docs/architecture.md");

#[test]
fn adr_0026_is_accepted_indexed_and_names_shipped_publication() {
    assert!(
        ADR_0026.contains("- Status: accepted"),
        "ADR 0026 must be accepted"
    );
    assert!(
        DECISIONS_INDEX.contains(
            "[ADR 0026: Publish change sets as governed branch proposals](0026-governed-branch-proposals.md)"
        ),
        "decisions index must link ADR 0026"
    );
    assert!(
        ADR_0026.contains("#731"),
        "ADR 0026 must name shipped #731 behavior as current"
    );
    assert!(
        ADR_0026.contains("compare-and-swaps one namespace published head")
            || ADR_0026.contains("compare-and-swap one namespace published head"),
        "ADR 0026 must record the published-head compare-and-swap"
    );
}

#[test]
fn adr_0026_records_rejected_discussion_726_alternatives() {
    assert!(
        ADR_0026.contains("Selector over already-published members"),
        "rejected selector alternative must appear in the ADR"
    );
    assert!(
        ADR_0026.contains("Draft members with visibility-gated publication"),
        "rejected draft-visibility alternative must appear in the ADR"
    );
    assert!(
        ADR_0026.contains("Rejected"),
        "alternatives must be recorded as rejected"
    );
}

#[test]
fn adr_0024_remains_the_branch_foundation_and_points_at_publication() {
    assert!(
        ADR_0024.starts_with("# ADR 0024: Evolve governed definitions through branches"),
        "ADR 0024 identity must remain the branch/revision foundation"
    );
    assert!(
        ADR_0024.contains("Related: ADR 0020, ADR 0026, Issue #666"),
        "ADR 0024 must point at ADR 0026 without rewriting its history"
    );
    assert!(
        !ADR_0024.contains("Superseded by: ADR 0026"),
        "ADR 0026 must not supersede the branch/revision foundation"
    );
}

#[test]
fn issue_733_is_evidence_work_not_open_design() {
    assert!(ADR_0026.contains("#733"), "ADR 0026 must list #733");
    assert!(
        ADR_0026.contains("not an open design question"),
        "#733 must be evidence work, not an open design question"
    );
    assert!(
        ADR_0026.contains("receipt")
            && ADR_0026.contains("compare-and-swap")
            && ADR_0026.contains("not-descendant")
            && ADR_0026.contains("close"),
        "#733 evidence obligations must be named"
    );
}

#[test]
fn maintained_docs_point_at_publication_adr() {
    assert!(
        DEFINITION_BRANCHES.contains("0026-governed-branch-proposals.md"),
        "definition-branches guide must point at ADR 0026"
    );
    assert!(
        ARCHITECTURE.contains("0026-governed-branch-proposals.md"),
        "architecture must point at ADR 0026"
    );
    assert!(
        ADR_0026.contains("Signatures, discovery, and package trust are not runtime grants"),
        "package identity must not be a grant"
    );
    assert!(
        ADR_0026.contains("Historical approval is not authority"),
        "live approver recheck must be required at merge"
    );
}
