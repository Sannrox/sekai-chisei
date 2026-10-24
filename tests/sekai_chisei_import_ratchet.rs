//! Ratchet for ADR 0096 rule 1: Sekai never depends on Chisei.
//!
//! Scans `crates/sekai-core/src/sekai` and `crates/sekai-core/src/db` for
//! `crate::chisei::<module>` and `crate::chisei_store` paths and compares them
//! with `ALLOWED`. A new edge fails; so does an allowlisted edge that no longer
//! exists, which keeps the list shrinking until it is empty and the rule is
//! absolute.

use std::collections::BTreeSet;
use std::fs;
use std::path::Path;

const NEEDLE: &str = "crate::chisei";

/// Sekai persistence crate; none of these modules may name Chisei.
const SEKAI_DIRS: &[&str] = &["crates/sekai-core/src/sekai", "crates/sekai-core/src/db"];

/// `<file> <chisei module>` pairs still waiting to move (ADR 0096 disposition
/// table). Remove an entry in the change that removes the edge.
const ALLOWED: &[&str] = &[];

#[test]
fn sekai_chisei_imports_only_shrink() {
    let mut found = BTreeSet::new();
    for dir in SEKAI_DIRS {
        collect(Path::new(dir), &mut found);
    }
    let allowed: BTreeSet<String> = ALLOWED.iter().map(|edge| edge.to_string()).collect();

    let added: Vec<_> = found.difference(&allowed).collect();
    assert!(
        added.is_empty(),
        "Sekai -> Chisei imports violate ADR 0096 rule 1; move shared vocabulary \
         into Sekai, add a Sekai-owned port that Chisei implements, or put code \
         that needs both planes in src/composition: {added:#?}"
    );
    let removed: Vec<_> = allowed.difference(&found).collect();
    assert!(
        removed.is_empty(),
        "these Sekai -> Chisei edges are gone; delete them from ALLOWED: {removed:#?}"
    );
}

fn collect(dir: &Path, found: &mut BTreeSet<String>) {
    let mut entries: Vec<_> = fs::read_dir(dir)
        .unwrap_or_else(|err| panic!("read {}: {err}", dir.display()))
        .map(|entry| entry.unwrap().path())
        .collect();
    entries.sort();
    for path in entries {
        if path.is_dir() {
            collect(&path, found);
        } else if path.extension().is_some_and(|ext| ext == "rs") {
            let file = path.to_string_lossy().replace('\\', "/");
            let source = fs::read_to_string(&path).unwrap();
            for module in chisei_modules(&source) {
                found.insert(format!("{file} {module}"));
            }
        }
    }
}

/// Chisei module names referenced as `crate::chisei::<module>`. A bare
/// `crate::chisei` path or a grouped `crate::chisei::{...}` import reports
/// `*`, so it cannot slip past the allowlist.
fn chisei_modules(source: &str) -> Vec<String> {
    let mut modules = Vec::new();
    for (start, _) in source.match_indices(NEEDLE) {
        let rest = &source[start + NEEDLE.len()..];
        // Chisei persistence is Chisei; `crate::chisei_principal` and
        // similar are other modules.
        if let Some(after) = rest.strip_prefix("_store")
            && !after.starts_with(|c: char| c.is_ascii_alphanumeric() || c == '_')
        {
            modules.push("chisei_store".into());
            continue;
        }
        if rest.starts_with(|c: char| c.is_ascii_alphanumeric() || c == '_') {
            continue;
        }
        let module: String = rest
            .strip_prefix("::")
            .map(|tail| {
                tail.chars()
                    .take_while(|c| c.is_ascii_alphanumeric() || *c == '_')
                    .collect()
            })
            .unwrap_or_default();
        modules.push(if module.is_empty() {
            "*".into()
        } else {
            module
        });
    }
    modules
}

#[test]
fn grouped_and_bare_chisei_paths_are_reported() {
    assert_eq!(
        chisei_modules("use crate::chisei::budget::BudgetTracker;"),
        ["budget"]
    );
    assert_eq!(
        chisei_modules("use crate::chisei::{budget, receipt};"),
        ["*"]
    );
    assert_eq!(chisei_modules("use crate::chisei;"), ["*"]);
    assert!(chisei_modules("use crate::chisei_principal::Map;").is_empty());
    assert_eq!(
        chisei_modules("use crate::chisei_store::ChiseiStore;"),
        ["chisei_store"]
    );
}
