//! Operator docs that name gated RPCs must name the experimental invocation gate.

use sekai_chisei::rpc_maturity::{RpcClassification, RpcMaturityTable};
use std::fs;
use std::path::{Path, PathBuf};

fn operator_pages(root: &Path) -> Vec<PathBuf> {
    let mut pages = Vec::new();
    for entry in fs::read_dir(root.join("docs")).expect("docs/") {
        let path = entry.expect("docs entry").path();
        if path.extension().is_some_and(|ext| ext == "md") && path.is_file() {
            pages.push(path);
        }
    }
    for rel in [
        "README.md",
        "adapters/README.md",
        "examples/README.md",
        "sdk/README.md",
    ] {
        pages.push(root.join(rel));
    }
    pages.sort();
    pages
}

#[test]
fn operator_docs_name_experimental_gate_when_they_name_gated_rpcs() {
    let table = RpcMaturityTable::load().expect("maturity table");
    let gated: Vec<&str> = table
        .entries
        .iter()
        .filter(|entry| {
            matches!(
                entry.classification,
                RpcClassification::Experimental | RpcClassification::Remove
            )
        })
        .map(|entry| entry.rpc.as_str())
        .collect();
    let root = Path::new(env!("CARGO_MANIFEST_DIR"));
    let mut missing = Vec::new();
    for page in operator_pages(root) {
        let text = fs::read_to_string(&page).unwrap_or_else(|error| {
            panic!("read {}: {error}", page.display());
        });
        if !gated.iter().any(|rpc| text.contains(rpc)) {
            continue;
        }
        if !text.contains("SEKAI_EXPERIMENTAL_RPCS") && !text.contains("experimental-rpcs") {
            missing.push(
                page.strip_prefix(root)
                    .unwrap_or(&page)
                    .display()
                    .to_string(),
            );
        }
    }
    assert!(
        missing.is_empty(),
        "operator docs name gated RPCs without SEKAI_EXPERIMENTAL_RPCS or experimental-rpcs: {missing:?}"
    );
}
