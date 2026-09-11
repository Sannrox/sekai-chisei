//! ADR 0060 index and related-pointer checks for Issues #817 and #818.

const ADR_0021: &str = include_str!("../docs/decisions/0021-defer-second-object-sync-source.md");
const ADR_0060: &str = include_str!("../docs/decisions/0060-additive-source-type-descriptors.md");
const DECISIONS_INDEX: &str = include_str!("../docs/decisions/README.md");
const OBJECT_SYNC: &str = include_str!("../docs/object-sync.md");
const RESEARCH: &str = include_str!("../docs/research/817-source-type-admission.md");

#[test]
fn adr_0060_is_indexed_and_names_the_source_issues() {
    assert!(
        DECISIONS_INDEX.contains(
            "[ADR 0060: Admit later object-sync kinds through additive registered descriptors](0060-additive-source-type-descriptors.md)"
        ),
        "decisions index must link ADR 0060"
    );
    assert!(ADR_0060.contains("#817"), "ADR 0060 must name Issue #817");
    assert!(ADR_0060.contains("#818"), "ADR 0060 must name Issue #818");
    assert!(
        ADR_0060.contains("{source}:{instance}#{record_kind}/{immutable_key}"),
        "ADR 0060 must name the additive identity form"
    );
    assert!(
        ADR_0060.contains("github:{owner}/{repo}#{number}"),
        "ADR 0060 must preserve the GitHub identity form"
    );
}

#[test]
fn related_docs_point_at_accepted_additive_descriptors() {
    assert!(
        ADR_0021.contains("0060-additive-source-type-descriptors.md"),
        "ADR 0021 must link the later additive-descriptor decision"
    );
    assert!(
        !ADR_0021.contains("Superseded by: [ADR 0060"),
        "ADR 0060 must not supersede ADR 0021"
    );
    assert!(
        OBJECT_SYNC.contains("0060-additive-source-type-descriptors.md"),
        "object-sync docs must name ADR 0060"
    );
    assert!(
        OBJECT_SYNC.contains("GitHub identity")
            && OBJECT_SYNC.contains("stay unchanged")
            && !OBJECT_SYNC.contains("unchanged until #818"),
        "object-sync docs must not imply GitHub identity changes when #818 registers"
    );
    assert!(
        RESEARCH.contains("0060-additive-source-type-descriptors.md"),
        "research #817 must record that ADR 0060 accepted the recommendation"
    );
}

fn markdown_section<'a>(text: &'a str, heading: &str) -> &'a str {
    let start = text
        .find(heading)
        .unwrap_or_else(|| panic!("missing heading {heading}"));
    let after = &text[start + heading.len()..];
    let end = after.find("\n## ").unwrap_or(after.len());
    &text[start..start + heading.len() + end]
}

#[test]
fn identity_section_lists_github_and_registered_grammars() {
    let section = markdown_section(OBJECT_SYNC, "## Identity and deletion");
    assert!(
        section.contains("github:{owner}/{repo}#{number}"),
        "Identity must keep the GitHub grammar"
    );
    assert!(
        section.contains("{source}:{instance}#{record_kind}/{immutable_key}"),
        "Identity must list the registered grammar"
    );
    assert!(
        section.contains("source=github") && section.contains("cannot be registered"),
        "Identity must separate github registration from the GitHub profile"
    );
    assert!(
        !section.contains("Source identity is `github:{owner}/{repo}#{number}`."),
        "Identity must not claim GitHub as the exclusive source identity"
    );
}

#[test]
fn batch_section_admits_github_digest_or_live_registered_descriptor() {
    let section = markdown_section(OBJECT_SYNC, "## Batch contract");
    assert!(
        section.contains("sha256:97a329c80d00af0525c6076aef9f8162471eee9c108cefae42f68a8309fb708a"),
        "Batch must keep the code-owned GitHub digest"
    );
    assert!(
        section.contains("live") && section.contains("registered descriptor"),
        "Batch must admit a live registered descriptor beside GitHub"
    );
    assert!(
        !section.contains("Any other digest fails as `unbound_type_revision`"),
        "Batch must not claim every non-GitHub digest fails"
    );
}
