//! `CLAUDE.md` is a compatibility copy of `AGENTS.md`. Keep them identical.

#[test]
fn claude_md_matches_agents_md() {
    let agents = include_str!("../AGENTS.md");
    let claude = include_str!("../CLAUDE.md");
    assert_eq!(
        agents, claude,
        "CLAUDE.md drifted from AGENTS.md; copy AGENTS.md over CLAUDE.md"
    );
}
