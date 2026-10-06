//! Hard rule for ADR 0092 rule 1: Chisei never depends on Sekai.
//!
//! Scans `src/chisei` for `crate::sekai::<module>` paths and fails on any.
//! Shared primitives live in Chisei and Sekai re-exports them; Sekai facts
//! reach Chisei through Chisei-owned ports; code that needs both planes,
//! including tests that seed Sekai fixtures, lives in `src/composition`.

use std::collections::BTreeSet;
use std::fs;
use std::path::Path;

const NEEDLE: &str = "crate::sekai";

#[test]
fn chisei_never_imports_sekai() {
    let mut found = BTreeSet::new();
    collect(Path::new("src/chisei"), &mut found);
    assert!(
        found.is_empty(),
        "Chisei -> Sekai imports violate ADR 0092 rule 1; route them through a \
         Chisei-owned port, move shared primitives into Chisei, or put code that \
         needs both planes in src/composition: {found:#?}"
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
