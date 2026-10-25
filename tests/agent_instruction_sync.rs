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
    assert!(
        agents.contains("`src/bin/sekaictl.rs`"),
        "AGENTS.md must name the operator CLI source that Cargo auto-discovers"
    );
    assert!(
        root.join("src/bin/sekaictl.rs").is_file(),
        "src/bin/sekaictl.rs must exist"
    );
}

#[test]
fn agents_md_names_every_workspace_crate() {
    let agents = include_str!("../AGENTS.md");
    let cargo = include_str!("../Cargo.toml");
    let start = cargo
        .find("members = [")
        .expect("Cargo.toml must declare workspace members");
    let body = &cargo[start + "members = [".len()..];
    let end = body.find(']').expect("workspace members list must close");
    let mut missing = Vec::new();
    for line in body[..end].lines() {
        let entry = line.trim().trim_end_matches(',').trim_matches('"');
        if entry.is_empty() {
            continue;
        }
        let name = entry.rsplit('/').next().expect("crate path has a name");
        let needle = format!("`{name}`");
        if !agents.contains(&needle) {
            missing.push(name.to_string());
        }
    }
    assert!(
        missing.is_empty(),
        "AGENTS.md must name every workspace crate; missing {missing:?}"
    );
}

/// Provenance locators in `docs/ontology/` name current source files.
/// After crate extracts, `src/chisei/`, `src/sekai/`, and `src/db/` are leftover.
#[test]
fn docs_ontology_provenance_paths_exist() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR"));
    let dir = root.join("docs/ontology");
    let mut stale = Vec::new();
    let mut missing = Vec::new();
    for entry in std::fs::read_dir(&dir).expect("docs/ontology") {
        let entry = entry.expect("ontology entry");
        let path = entry.path();
        if path.extension().and_then(|e| e.to_str()) != Some("json") {
            continue;
        }
        let text = std::fs::read_to_string(&path).expect("read ontology json");
        for (idx, line) in text.lines().enumerate() {
            if line.contains("\"src/chisei/")
                || line.contains("\"src/chisei_store/")
                || line.contains("\"src/sekai/")
                || line.contains("\"src/db/")
            {
                stale.push(format!("{}:{}", path.display(), idx + 1));
            }
        }
        let mut rest = text.as_str();
        while let Some(start) = rest.find('"') {
            rest = &rest[start + 1..];
            let Some(end) = rest.find('"') else {
                break;
            };
            let quoted = &rest[..end];
            rest = &rest[end + 1..];
            let head = quoted.split(';').next().unwrap_or(quoted);
            if !(head.starts_with("src/")
                || head.starts_with("crates/")
                || head.starts_with("docs/"))
            {
                continue;
            }
            if !(head.ends_with(".rs") || head.ends_with(".md") || head.ends_with(".json")) {
                continue;
            }
            if !root.join(head).is_file() {
                missing.push(format!("{} -> {quoted}", path.display()));
            }
        }
    }
    assert!(
        stale.is_empty(),
        "docs/ontology still names pre-extract paths: {stale:?}"
    );
    assert!(
        missing.is_empty(),
        "docs/ontology provenance locators must exist: {missing:?}"
    );
}
