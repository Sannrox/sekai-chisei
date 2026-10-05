//! Ratchet for ADR 0092 rule 1: Chisei never depends on Sekai.
//!
//! Scans `src/chisei` for `crate::sekai::<module>` paths and compares the
//! (file, module) pairs with `ALLOWED`. A new pair fails, and so does an
//! allowed pair that no longer exists, so the list only shrinks. Follow-up
//! Issues (#1240, #1241, #1242) remove entries; when `ALLOWED` is empty this
//! becomes a hard rule.

use std::collections::BTreeSet;
use std::fs;
use std::path::Path;

/// Existing Chisei -> Sekai imports, one `"<file> <sekai module>"` per entry.
const ALLOWED: &[&str] = &[
    "src/chisei/capability.rs audit",
    "src/chisei/capability.rs ontology",
    "src/chisei/egress.rs schema",
    "src/chisei/epistemic_descriptor.rs evidence_store",
    "src/chisei/epistemic_descriptor.rs retrieval",
    "src/chisei/external_action_lifecycle.rs action_policy",
    "src/chisei/learning_change.rs learning",
    "src/chisei/learning_change.rs schema",
    "src/chisei/pipeline.rs capacity",
    "src/chisei/pipeline.rs evidence",
    "src/chisei/pipeline.rs evidence_store",
    "src/chisei/pipeline.rs schema",
    "src/chisei/sekai_facts.rs schema",
    "src/chisei/system_one_action.rs governed_action_type",
    "src/chisei/system_one_action.rs schema",
];

const NEEDLE: &str = "crate::sekai";

#[test]
fn chisei_imports_of_sekai_only_shrink() {
    let mut found = BTreeSet::new();
    collect(Path::new("src/chisei"), &mut found);
    let allowed: BTreeSet<String> = ALLOWED.iter().map(|entry| entry.to_string()).collect();

    let added: Vec<_> = found.difference(&allowed).collect();
    let removed: Vec<_> = allowed.difference(&found).collect();
    assert!(
        added.is_empty(),
        "new Chisei -> Sekai imports violate ADR 0092 rule 1; route them through a \
         Chisei-owned port instead: {added:#?}"
    );
    assert!(
        removed.is_empty(),
        "these imports are gone; remove them from ALLOWED so the ratchet keeps \
         shrinking: {removed:#?}"
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
            for module in sekai_modules(&source) {
                found.insert(format!("{file} {module}"));
            }
        }
    }
}

/// Sekai module names referenced as `crate::sekai::<module>`. A bare
/// `crate::sekai` path or a grouped `crate::sekai::{...}` import reports `*`,
/// so it cannot slip past the allowlist.
fn sekai_modules(source: &str) -> Vec<String> {
    let mut modules = Vec::new();
    for (start, _) in source.match_indices(NEEDLE) {
        let rest = &source[start + NEEDLE.len()..];
        // `crate::sekai_facts` and similar are other modules, not Sekai.
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
fn grouped_and_bare_sekai_paths_are_reported() {
    assert_eq!(
        sekai_modules("use crate::sekai::audit::Decision;"),
        ["audit"]
    );
    assert_eq!(sekai_modules("use crate::sekai::{audit, ledger};"), ["*"]);
    assert_eq!(sekai_modules("use crate::sekai;"), ["*"]);
    assert!(sekai_modules("use crate::sekai_facts::Reader;").is_empty());
}
