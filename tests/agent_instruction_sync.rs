//! `CLAUDE.md` is a compatibility copy of `AGENTS.md`. Keep them identical.

use std::path::Path;

#[test]
fn claude_md_matches_agents_md() {
    let agents = include_str!("../AGENTS.md");
    let claude = include_str!("../CLAUDE.md");
    assert_eq!(
        agents, claude,
        "CLAUDE.md drifted from AGENTS.md; copy AGENTS.md over CLAUDE.md"
    );
}

#[test]
fn agents_md_names_shipped_plane_bin_sources() {
    let agents = include_str!("../AGENTS.md");
    assert!(
        agents.contains("`src/bin/sekai.rs`") && agents.contains("`src/bin/chisei.rs`"),
        "AGENTS.md must name the two-plane bin sources that Cargo.toml ships"
    );
    let cargo = include_str!("../Cargo.toml");
    assert!(
        cargo.contains("name = \"sekai-plane\"") && cargo.contains("path = \"src/bin/sekai.rs\""),
        "Cargo.toml must declare sekai-plane at src/bin/sekai.rs"
    );
    assert!(
        cargo.contains("name = \"chisei-plane\"") && cargo.contains("path = \"src/bin/chisei.rs\""),
        "Cargo.toml must declare chisei-plane at src/bin/chisei.rs"
    );
    let root = Path::new(env!("CARGO_MANIFEST_DIR"));
    assert!(
        root.join("src/bin/sekai.rs").is_file(),
        "src/bin/sekai.rs must exist"
    );
    assert!(
        root.join("src/bin/chisei.rs").is_file(),
        "src/bin/chisei.rs must exist"
    );
    assert!(
        agents.contains("SEKAI_DB_PATH") && agents.contains("CHISEI_DB_PATH"),
        "AGENTS.md must name the combined dest-pair store variables"
    );
    assert!(
        agents.contains("`fmt-check` is `fmt --all -- --check`"),
        "AGENTS.md must describe the fmt-check alias as it is in .cargo/config.toml"
    );
}
