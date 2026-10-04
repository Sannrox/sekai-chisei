//! Ratchet for ADR 0083 rule 6: Chisei code does not receive `RuntimeDb`.
//!
//! Counts `.runtime()` and `.runtime_arc()` calls per file under `src/chisei`
//! and compares them with `ALLOWED`. Chisei-owned persistence goes through the
//! Chisei store traits in `crate::db::store`; Sekai fact reads go through the
//! Chisei-owned Sekai read port. A file whose count rises fails, and so does a
//! file whose count fell without lowering `ALLOWED`, so the totals only shrink.
//! `ChiseiStore::runtime()` leaves the public surface once no caller needs it.

use std::collections::BTreeMap;
use std::fs;
use std::path::Path;

/// Remaining backend-facade calls, as `(file, count)`.
const ALLOWED: &[(&str, usize)] = &[
    ("src/chisei/affinity.rs", 7),
    ("src/chisei/capability.rs", 4),
    ("src/chisei/cross_store_admission.rs", 6),
    ("src/chisei/data_quality.rs", 4),
    ("src/chisei/gunshi.rs", 2),
    ("src/chisei/gunshi_dispatch.rs", 1),
    ("src/chisei/kioku.rs", 6),
    ("src/chisei/learning_change.rs", 13),
    ("src/chisei/lookup_first.rs", 34),
    ("src/chisei/pipeline.rs", 65),
    ("src/chisei/remote_sekai.rs", 2),
    ("src/chisei/sekai_facts.rs", 6),
];

const NEEDLES: &[&str] = &[".runtime()", ".runtime_arc()"];

#[test]
fn chisei_runtime_db_calls_only_shrink() {
    let mut found = BTreeMap::new();
    collect(Path::new("src/chisei"), &mut found);
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
        } else if path.extension().is_some_and(|ext| ext == "rs") {
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
