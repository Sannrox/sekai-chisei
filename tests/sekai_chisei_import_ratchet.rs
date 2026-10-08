//! Ratchet for ADR 0096 rule 1: Sekai never depends on Chisei.
//!
//! Scans `src/sekai` for `crate::chisei::<module>` paths and compares them
//! with `ALLOWED`, the edges that existed when ADR 0096 was accepted. A new
//! edge fails; so does an allowlisted edge that no longer exists, which keeps
//! the list shrinking until it is empty and the rule is absolute.

use std::collections::BTreeSet;
use std::fs;
use std::path::Path;

const NEEDLE: &str = "crate::chisei";

/// `<file> <chisei module>` pairs still waiting to move (ADR 0096 disposition
/// table). Remove an entry in the change that removes the edge.
const ALLOWED: &[&str] = &[
    "src/sekai/action_describe_preview.rs budget",
    "src/sekai/action_describe_preview.rs system_one_action",
    "src/sekai/action_instance_admission.rs budget",
    "src/sekai/action_instance_admission.rs receipt",
    "src/sekai/action_instance_admission.rs system_one_action",
    "src/sekai/action_work_lifecycle.rs receipt",
    "src/sekai/chisei_principal.rs principal",
    "src/sekai/chisei_projection.rs epistemic_descriptor",
    "src/sekai/chisei_projection.rs system_one_action",
    "src/sekai/execution_evidence.rs external_action",
    "src/sekai/execution_evidence.rs external_permit",
    "src/sekai/execution_evidence.rs receipt",
    "src/sekai/peer_import.rs receipt",
    "src/sekai/workflow_action.rs budget",
    "src/sekai/workflow_action.rs receipt",
];

#[test]
fn sekai_chisei_imports_only_shrink() {
    let mut found = BTreeSet::new();
    collect(Path::new("src/sekai"), &mut found);
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
        // `crate::chisei_principal` and similar are other modules, not Chisei.
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
}
