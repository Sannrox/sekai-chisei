//! Operator docs that name gated RPCs must name the experimental invocation gate.
//! #1095: advertised "supported" / dual-backend sentences must not cover gated
//! RPCs. #1086: the product loop is dual-backend, so its PostgreSQL cells say so.

use sekai_chisei::mcp_adapter::well_known_tools;
use sekai_chisei::rpc_maturity::{
    RpcClassification, RpcMaturityTable, capability_backing_rpc, capability_is_stable,
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
fn operator_docs_advertise_postgres_for_ontology_apply() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR"));
    let contract = root.join("docs/integration-contract.md");
    let text = fs::read_to_string(&contract).expect("integration-contract");
    let coverage = text
        .split("## Language and backend coverage")
        .nth(1)
        .expect("coverage section");
    let row = coverage
        .lines()
        .find(|line| line.contains("Ontology apply"))
        .expect("ontology apply row");
    let cells: Vec<&str> = row.split('|').map(str::trim).collect();
    assert_eq!(
        cells.get(6).copied(),
        Some("yes"),
        "ontology apply runs on PostgreSQL (#1086): {row}"
    );
}

/// #1205: catalog copy must follow rpc_maturity, not invent an experimental
/// reason for projected evaluation tools.
fn mcp_allowlist_paragraph(catalog: &str) -> &str {
    let heading = catalog
        .find("### MCP and SDK projections")
        .expect("MCP projection heading");
    let section = catalog[heading..]
        .split("\nThe SDK bindings")
        .next()
        .expect("MCP section before SDK bindings");
    let start = section
        .find("returns only the v1 allowlist:")
        .expect("MCP v1 allowlist sentence");
    &section[start..]
}

#[test]
fn capability_catalog_mcp_reason_matches_stable_evaluation_maturity() {
    let table = RpcMaturityTable::load().expect("maturity table");
    let root = Path::new(env!("CARGO_MANIFEST_DIR"));
    let catalog = fs::read_to_string(root.join("docs/capability-catalog.md")).expect("catalog");
    let allowlist = mcp_allowlist_paragraph(&catalog);
    let projected: Vec<&str> = well_known_tools().into_iter().collect();

    for tool in ["chisei.evaluation.resolve", "chisei.evaluation.execute"] {
        assert!(
            projected.contains(&tool),
            "{tool} must stay on the shipped MCP allowlist while its RPC is stable"
        );
        assert!(
            capability_is_stable(tool),
            "{tool} backing RPC must be stable in rpc_maturity"
        );
        let rpc = capability_backing_rpc(tool).expect("evaluation tool maps to an RPC");
        let class = table
            .entries
            .iter()
            .find(|entry| entry.rpc == rpc)
            .unwrap_or_else(|| panic!("{rpc} missing from maturity table"))
            .classification;
        assert_eq!(
            class,
            RpcClassification::Stable,
            "{rpc} maturity is the catalog reason, not experimental"
        );
        assert!(
            allowlist.contains(tool),
            "capability catalog must list projected tool {tool}"
        );
        assert!(
            allowlist.contains(rpc),
            "capability catalog must list projected RPC {rpc}"
        );
    }

    assert!(
        allowlist.contains("`stable`"),
        "capability catalog must give stable maturity as the listing reason: {allowlist}"
    );
    assert!(
        !allowlist.to_ascii_lowercase().contains("experimental"),
        "capability catalog must not call stable evaluation RPCs experimental: {allowlist}"
    );

    for tool in &projected {
        assert!(
            allowlist.contains(tool),
            "capability catalog MCP allowlist must list projected tool {tool}"
        );
    }
}
