//! Ratchet for ADR 0083 rule 6: Chisei code does not receive `RuntimeDb`.
//!
//! Counts `.runtime()` and `.runtime_arc()` calls per file under `crates/chisei-core/src/chisei`
//! and compares them with `ALLOWED`. Chisei-owned persistence goes through the
//! Chisei store traits in `crate::chisei_store`; Sekai fact reads go through the
//! Chisei-owned Sekai read port. A file whose count rises fails, and so does a
//! file whose count fell without lowering `ALLOWED`, so the totals only shrink.
//! Domain modules must not call `ChiseiStore::runtime()`. In-process Sekai
//! port impls that still name `SekaiStore::runtime()` stay on `ALLOWED`.

use std::collections::BTreeMap;
use std::fs;
use std::path::Path;

/// Remaining `.runtime()` / `.runtime_arc()` calls on the in-process Sekai
/// store (orphan-rule port impls). Empty once those reads go through methods
/// on `SekaiStore` that do not name `RuntimeDb`.
const ALLOWED: &[(&str, usize)] = &[
    ("crates/chisei-core/src/chisei/sekai_commit.rs", 1),
    ("crates/chisei-core/src/chisei/sekai_facts.rs", 3),
];

const NEEDLES: &[&str] = &[".runtime()", ".runtime_arc()"];

#[test]
fn chisei_runtime_db_calls_only_shrink() {
    let mut found = BTreeMap::new();
    collect(Path::new("crates/chisei-core/src/chisei"), &mut found);
    let allowed: BTreeMap<String, usize> = ALLOWED
        .iter()
        .map(|(file, count)| (file.to_string(), *count))
        .collect();

    let grown: Vec<_> = found
        .iter()
        .filter(|(file, count)| **count > allowed.get(*file).copied().unwrap_or(0))
        .map(|(file, count)| {
            format!(
                "{file}: {count} (allowed {})",
                allowed.get(file).copied().unwrap_or(0)
            )
        })
        .collect();
    assert!(
        grown.is_empty(),
        "new RuntimeDb calls in Chisei violate ADR 0083 rule 6; use the Chisei store \
         traits in crate::db::store or the Sekai read port instead: {grown:#?}"
    );

    let shrunk: Vec<_> = allowed
        .iter()
        .filter(|(file, count)| found.get(*file).copied().unwrap_or(0) < **count)
        .map(|(file, count)| {
            format!(
                "{file}: {} (allowed {count})",
                found.get(file).copied().unwrap_or(0)
            )
        })
        .collect();
    assert!(
        shrunk.is_empty(),
        "these files call RuntimeDb less often; lower ALLOWED so the ratchet keeps \
         shrinking: {shrunk:#?}"
    );
}

fn collect(dir: &Path, found: &mut BTreeMap<String, usize>) {
    let mut entries: Vec<_> = fs::read_dir(dir)
        .unwrap_or_else(|err| panic!("read {}: {err}", dir.display()))
        .map(|entry| entry.unwrap().path())
        .collect();
    entries.sort();
    for path in entries {
        if path.is_dir() {
            collect(&path, found);
        } else if path.extension().is_some_and(|ext| ext == "rs")
            && !path
                .file_name()
                .and_then(|name| name.to_str())
                .is_some_and(|name| name.ends_with("_tests.rs"))
        {
            let source = fs::read_to_string(&path).unwrap();
            let count: usize = NEEDLES
                .iter()
                .map(|needle| source.matches(needle).count())
                .sum();
            if count > 0 {
                let file = path.to_string_lossy().replace('\\', "/");
                found.insert(file, count);
            }
        }
    }
}
