//! `sekaictl admin connectors new`: copy the connector template (#1409).
//!
//! The template is the workspace crate `crates/sekai-connector-template`, so
//! it builds and passes conformance against the current SDK on every change.
//! Generation only renames the crate and points its SDK and protocol
//! dependencies at a checkout or at the repository.

use std::path::{Path, PathBuf};

const TEMPLATE_NAME: &str = "sekai-connector-template";
const REPOSITORY: &str = "https://github.com/Sannrox/sekai-chisei";

macro_rules! template_files {
    ($($path:literal),* $(,)?) => {
        &[$(($path, include_str!(concat!("../crates/sekai-connector-template/", $path)))),*]
    };
}

const FILES: &[(&str, &str)] = template_files![
    "Cargo.toml",
    "README.md",
    "connector.json",
    "src/config.rs",
    "src/fake.rs",
    "src/lib.rs",
    "src/main.rs",
    "src/source.rs",
    "src/transport.rs",
    "tests/conformance.rs",
];

/// Lowercase strict and reserved keywords: the crate name becomes an identifier.
const RUST_KEYWORDS: &[&str] = &[
    "abstract", "as", "async", "await", "become", "box", "break", "const", "continue", "crate",
    "do", "dyn", "else", "enum", "extern", "false", "final", "fn", "for", "gen", "if", "impl",
    "in", "let", "loop", "macro", "match", "mod", "move", "mut", "override", "priv", "pub", "ref",
    "return", "self", "static", "struct", "super", "trait", "true", "try", "type", "typeof",
    "unsafe", "unsized", "use", "virtual", "where", "while", "yield",
];

/// Where the generated project takes `sekai-source-sdk` and `sekai-proto` from.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SdkSource {
    /// A local checkout of this repository.
    Checkout(PathBuf),
    /// This repository on GitHub.
    Repository,
}

/// Write a new connector project named `name` into the empty or missing
/// directory `out`. Returns the written paths.
pub fn generate(name: &str, out: &Path, sdk: &SdkSource) -> Result<Vec<PathBuf>, String> {
    let valid = name.len() <= 64
        && name.starts_with(|c: char| c.is_ascii_lowercase())
        && name
            .chars()
            .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-');
    if !valid {
        return Err("connector name must be lowercase letters, digits, and '-'".into());
    }
    let crate_ident = name.replace('-', "_");
    if RUST_KEYWORDS.contains(&crate_ident.as_str()) {
        return Err(format!("connector name {name:?} is a Rust keyword"));
    }
    if out
        .read_dir()
        .is_ok_and(|mut entries| entries.next().is_some())
    {
        return Err(format!("{} is not empty", out.display()));
    }
    let template_ident = TEMPLATE_NAME.replace('-', "_");
    let mut written = Vec::with_capacity(FILES.len());
    for (relative, contents) in FILES {
        let mut contents = contents
            .replace(TEMPLATE_NAME, name)
            .replace(&template_ident, &crate_ident);
        if *relative == "Cargo.toml" {
            contents = manifest(&contents, sdk);
        }
        let path = out.join(relative);
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)
                .map_err(|error| format!("cannot create {}: {error}", parent.display()))?;
        }
        std::fs::write(&path, contents)
            .map_err(|error| format!("cannot write {}: {error}", path.display()))?;
        written.push(path);
    }
    Ok(written)
}

/// Repoint `path = "../<crate>"` dependencies and make the project its own
/// workspace, so it builds wherever it is generated.
fn manifest(contents: &str, sdk: &SdkSource) -> String {
    let mut lines = contents
        .lines()
        .map(|line| match line.split_once("path = \"../") {
            Some((head, tail)) => {
                let krate = tail.trim_end_matches(['"', ' ', '}']);
                match sdk {
                    // A JSON string is a valid TOML basic string.
                    SdkSource::Checkout(root) => format!(
                        "{head}path = {} }}",
                        serde_json::Value::from(
                            root.join("crates").join(krate).display().to_string()
                        )
                    ),
                    SdkSource::Repository => format!("{head}git = \"{REPOSITORY}\" }}"),
                }
            }
            None => line.to_string(),
        })
        .collect::<Vec<_>>();
    lines.push(String::new());
    lines.push("[workspace]".into());
    lines.join("\n") + "\n"
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn manifest_points_dependencies_at_the_chosen_sdk() {
        let template = FILES[0].1;
        let checkout = manifest(template, &SdkSource::Checkout("/src/chisei".into()));
        assert!(checkout.contains(
            r#"sekai-source-sdk = { version = "1.3.0", path = "/src/chisei/crates/sekai-source-sdk" }"#
        ));
        let quoted = manifest(template, &SdkSource::Checkout(r#"/src/a"b\c"#.into()));
        assert!(quoted.contains(r#"path = "/src/a\"b\\c/crates/sekai-proto" }"#));
        let repository = manifest(template, &SdkSource::Repository);
        assert!(repository.contains(&format!(
            r#"sekai-proto = {{ version = "1.1.0", git = "{REPOSITORY}" }}"#
        )));
        assert!(!repository.contains("path = "));
        assert!(repository.ends_with("[workspace]\n"));
    }

    #[test]
    fn generate_renames_the_crate_and_refuses_bad_names_and_full_directories() {
        let out = tempfile::tempdir().unwrap();
        let written = generate("acme-crm", out.path(), &SdkSource::Repository).unwrap();
        assert_eq!(written.len(), FILES.len());
        let main = std::fs::read_to_string(out.path().join("src/main.rs")).unwrap();
        assert!(main.contains("use acme_crm::{RunOutcome, run_once};"));
        for path in &written {
            let text = std::fs::read_to_string(path).unwrap();
            assert!(!text.contains(TEMPLATE_NAME), "{}", path.display());
        }
        assert!(generate("acme-crm", out.path(), &SdkSource::Repository).is_err());
        assert!(generate("Acme", &out.path().join("other"), &SdkSource::Repository).is_err());
        assert!(generate("type", &out.path().join("other"), &SdkSource::Repository).is_err());
    }
}
