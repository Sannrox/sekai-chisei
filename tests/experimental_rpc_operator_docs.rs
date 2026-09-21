//! Operator docs that name gated RPCs must name the experimental invocation gate.
//! #1095: advertised "supported" / dual-backend sentences must not cover gated
//! or Postgres-fail-closed product-loop RPCs.

use sekai_chisei::rpc_maturity::{
    RpcClassification, RpcMaturityTable, postgres_fail_closed_product_loop_rpcs,
};
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

#[test]
fn operator_docs_do_not_claim_supported_for_gated_rpcs() {
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
    let mut bad = Vec::new();
    for page in operator_pages(root) {
        let text = fs::read_to_string(&page).unwrap_or_else(|error| {
            panic!("read {}: {error}", page.display());
        });
        let rel = page
            .strip_prefix(root)
            .unwrap_or(&page)
            .display()
            .to_string();
        for line in text.lines() {
            let trimmed = line.trim();
            if !trimmed.starts_with('|') || !trimmed.contains("| supported |") {
                continue;
            }
            for rpc in &gated {
                if trimmed.contains(*rpc) {
                    bad.push(format!("{rel}: {rpc}"));
                }
            }
        }
    }
    assert!(
        bad.is_empty(),
        "operator docs claim supported for gated RPCs: {bad:?}"
    );
}

#[test]
fn operator_docs_do_not_advertise_postgres_yes_for_fail_closed_loop_rpcs() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR"));
    let contract = root.join("docs/integration-contract.md");
    let text = fs::read_to_string(&contract).expect("integration-contract");
    let coverage = text
        .split("## Language and backend coverage")
        .nth(1)
        .expect("coverage section");
    for rpc in postgres_fail_closed_product_loop_rpcs() {
        assert!(
            text.contains(rpc),
            "integration-contract must still name fail-closed loop rpc {rpc}"
        );
    }
    assert!(
        coverage.contains("fail-closed"),
        "integration-contract coverage must say PostgreSQL fail-closed for ontology apply"
    );
    for line in coverage.lines() {
        if !line.contains("Ontology apply") {
            continue;
        }
        let cells: Vec<&str> = line.split('|').map(str::trim).collect();
        let postgres = cells.get(6).copied().unwrap_or("");
        assert!(
            postgres.contains("fail-closed"),
            "ontology apply PostgreSQL cell must be fail-closed, got {postgres:?}"
        );
        assert_ne!(postgres, "yes");
    }
}
