//! Supported integration-contract map (#834 / #1095).

use sekai_chisei::rpc_maturity::{
    RpcClassification, RpcMaturityTable, advertised_product_loop_rpcs, advertised_sdk_typed_rpcs,
};
use std::collections::BTreeSet;
use std::fs;
use std::path::Path;

const DOC: &str = include_str!("../docs/integration-contract.md");
const SEKAI_PROTO: &str = include_str!("../proto/sekai.proto");
const CHISEI_PROTO: &str = include_str!("../proto/chisei.proto");
const ONTOLOGY_CLI: &str = include_str!("../src/ontology_product_cli.rs");
const SDK_TS: &str = include_str!("../sdk/typescript/client.ts");
const SDK_PY: &str = include_str!("../sdk/python/sekai_client.py");
const RUNTIME_DB: &str = include_str!("../src/db/runtime_db.rs");

fn rows() -> Vec<Vec<String>> {
    let start = DOC
        .find("<!-- integration-contract-rows -->")
        .expect("row marker");
    let end = DOC
        .find("<!-- /integration-contract-rows -->")
        .expect("end marker");
    DOC[start..end]
        .lines()
        .filter(|line| line.starts_with("| ") && !line.contains("Surface") && !line.contains("---"))
        .map(|line| {
            line.trim()
                .trim_matches('|')
                .split('|')
                .map(|cell| cell.trim().to_string())
                .collect()
        })
        .collect()
}

fn rpc_exists(rpc: &str) -> bool {
    if rpc == "—" {
        return true;
    }
    if rpc.starts_with("HTTP ") {
        return DOC.contains("chisei.provider-capabilities/v1");
    }
    if rpc.contains("sekaictl") {
        return Path::new("docs/sdk-packages.md").exists();
    }
    if rpc.contains("sekai-mcp") {
        return Path::new("src/bin/sekai_mcp.rs").exists();
    }
    if rpc.contains("POST /") || rpc.contains("/mcp") {
        return Path::new("src/http_projection.rs").exists();
    }
    if rpc.contains("TypeScript") || rpc.contains("goldens") {
        return Path::new("src/http_codegen.rs").exists();
    }
    let name = rpc
        .rsplit('.')
        .next()
        .unwrap_or(rpc)
        .trim_matches('`')
        .trim();
    let needle = format!("rpc {name}(");
    if rpc.contains("ChiseiService") {
        CHISEI_PROTO.contains(&needle)
    } else {
        SEKAI_PROTO.contains(&needle)
    }
}

fn markdown_target(cell: &str) -> Option<String> {
    let start = cell.find('(')?;
    let end = cell[start + 1..].find(')')?;
    Some(cell[start + 1..start + 1 + end].to_string())
}

#[test]
fn supported_rows_link_protocol_docs_and_proof() {
    let mut supported = 0;
    for row in rows() {
        assert_eq!(row.len(), 6, "{row:?}");
        let status = row[1].as_str();
        let rpc = row[3].trim_matches('`');
        let docs = &row[4];
        let proof = &row[5];
        match status {
            "supported" | "experimental" => {
                supported += 1;
                assert!(rpc_exists(rpc), "missing RPC {rpc}");
                let doc_path = markdown_target(docs).expect("docs link");
                assert!(
                    Path::new("docs").join(&doc_path).exists()
                        || Path::new(&doc_path).exists()
                        || Path::new("docs")
                            .join(doc_path.trim_start_matches("../"))
                            .exists(),
                    "missing docs {doc_path}"
                );
                let proof_path = proof.trim_matches('`');
                assert!(Path::new(proof_path).exists(), "missing proof {proof_path}");
            }
            "unavailable" | "planned" => {
                assert_eq!(
                    rpc, "—",
                    "unshipped surface {} must not name an RPC",
                    row[0]
                );
            }
            other => panic!("unknown status {other}"),
        }
    }
    assert!(
        supported >= 16,
        "expected a complete supported map, got {supported}"
    );
}

#[test]
fn gaps_are_named_and_not_claimed_as_shipped() {
    let lowered = DOC.to_ascii_lowercase();
    for gap in ["objectset", "preview", "subscription"] {
        assert!(lowered.contains(gap), "missing gap {gap}");
    }
    assert!(DOC.contains("#835"));
    assert!(DOC.contains("#836"));
    assert!(DOC.contains("#838"));
    let compact = DOC.split_whitespace().collect::<Vec<_>>().join(" ");
    assert!(compact.contains("does not add a protocol package"));
    assert!(compact.contains("or browser access to server credentials"));
    assert!(!compact.contains("grants browser access to server credentials"));
}

#[test]
fn define_query_invoke_receipt_path_is_documented() {
    for step in advertised_product_loop_rpcs() {
        assert!(DOC.contains(step), "advertised loop missing {step}");
    }
}

fn contract_rpc_name(rpc: &str) -> Option<&str> {
    let trimmed = rpc.trim_matches('`');
    if trimmed == "—" || trimmed.contains("sekaictl") || trimmed.contains("sekai-mcp") {
        return None;
    }
    if trimmed.starts_with("HTTP ") || trimmed.contains("POST /") || trimmed.contains("goldens") {
        return None;
    }
    if !trimmed.contains("Service.") {
        return None;
    }
    trimmed.rsplit('.').next()
}

fn source_calls_rpc(source: &str, rpc: &str) -> bool {
    let snake = rpc
        .chars()
        .enumerate()
        .flat_map(|(i, ch)| {
            if i > 0 && ch.is_uppercase() {
                vec!['_', ch.to_ascii_lowercase()]
            } else {
                vec![ch.to_ascii_lowercase()]
            }
        })
        .collect::<String>();
    source.contains(rpc) || source.contains(&snake) || source.contains(&format!("\"{rpc}\""))
}

#[test]
fn supported_rpc_rows_match_maturity_and_cli_sdk_greps() {
    let table = RpcMaturityTable::load().expect("maturity table");
    let loop_rpcs: BTreeSet<&str> = advertised_product_loop_rpcs().iter().copied().collect();
    let sdk_extra: BTreeSet<&str> = advertised_sdk_typed_rpcs().iter().copied().collect();
    let mut advertised = BTreeSet::new();
    for row in rows() {
        let status = row[1].clone();
        let Some(rpc) = contract_rpc_name(&row[3]).map(str::to_string) else {
            continue;
        };
        let entry = table
            .entries
            .iter()
            .find(|entry| entry.rpc == rpc)
            .unwrap_or_else(|| panic!("contract RPC {rpc} missing from maturity table"));
        match status.as_str() {
            "supported" => {
                assert_eq!(
                    entry.classification,
                    RpcClassification::Stable,
                    "supported contract row {rpc} must be classified stable"
                );
                if loop_rpcs.contains(rpc.as_str()) || sdk_extra.contains(rpc.as_str()) {
                    advertised.insert(rpc);
                    continue;
                }
                assert!(
                    rpc == "DiscoverCapabilities",
                    "supported contract RPC {rpc} is not in the sekaictl/SDK advertised loop"
                );
            }
            "experimental" => {
                assert_eq!(
                    entry.classification,
                    RpcClassification::Experimental,
                    "experimental contract row {rpc} must be classified experimental"
                );
            }
            "unavailable" => {
                panic!("unavailable contract row names {rpc}, which the maturity table classifies")
            }
            _ => {}
        }
    }
    for rpc in advertised_product_loop_rpcs() {
        assert!(
            advertised.contains(*rpc),
            "advertised loop rpc {rpc} missing from supported contract rows"
        );
        let in_cli = source_calls_rpc(ONTOLOGY_CLI, rpc);
        let in_sdk = source_calls_rpc(SDK_TS, rpc) || source_calls_rpc(SDK_PY, rpc);
        assert!(
            in_cli || in_sdk,
            "advertised loop rpc {rpc} is not called by sekaictl ontology or typed SDK helpers"
        );
        let consumer = table
            .entries
            .iter()
            .find(|entry| entry.rpc == *rpc)
            .map(|entry| entry.consumer.as_str())
            .unwrap_or("");
        if in_cli {
            assert!(
                consumer.split(',').any(|part| part.trim() == "cli"),
                "{rpc} is called by sekaictl but maturity consumer is {consumer:?}"
            );
        }
        if in_sdk {
            assert!(
                consumer.split(',').any(|part| part.trim() == "sdk"),
                "{rpc} is called by the typed SDK but maturity consumer is {consumer:?}"
            );
        }
    }
}

#[test]
fn product_loop_mutations_do_not_fail_closed_on_postgres() {
    // #1086: audited ontology writes, namespace roles, and credential
    // creation back the product loop on both community backends.
    for method in [
        "upsert_ontology_class_with_audit",
        "upsert_ontology_relation_with_audit",
        "list_namespace_roles_for_principal",
        "list_unbound_credentials",
    ] {
        let needle = format!("{method} is unavailable on the PostgreSQL community runtime");
        assert!(
            !RUNTIME_DB.contains(&needle),
            "RuntimeDb still fails closed for {method}"
        );
    }
    let coverage_start = DOC
        .find("## Language and backend coverage")
        .expect("coverage section");
    let coverage = &DOC[coverage_start..];
    assert!(
        !coverage.contains("fail-closed"),
        "integration-contract coverage must not list product-loop rows as fail-closed"
    );
    assert!(
        !coverage.contains("| Object read / list |"),
        "integration-contract must not advertise Object read/list as the product-loop query"
    );
}

#[test]
fn advertised_loop_sources_exist() {
    for rel in [
        "src/ontology_product_cli.rs",
        "sdk/typescript/client.ts",
        "sdk/python/sekai_client.py",
        "src/db/runtime_db.rs",
    ] {
        assert!(Path::new(rel).exists(), "missing {rel}");
        assert!(!fs::read_to_string(rel).unwrap().is_empty(), "{rel} empty");
    }
}

#[test]
fn action_approval_row_tracks_decide_maturity() {
    // #1151: the park-and-decide surface is on the wire, so the contract
    // must name it at its maturity rather than report it unavailable.
    let row = rows()
        .into_iter()
        .find(|row| row[0].starts_with("Action approval"))
        .expect("action approval coverage row");
    assert_eq!(contract_rpc_name(&row[3]), Some("DecideActionInstance"));
    let entry = RpcMaturityTable::load()
        .expect("maturity table")
        .entries
        .into_iter()
        .find(|entry| entry.rpc == "DecideActionInstance")
        .expect("DecideActionInstance maturity");
    let expected = match entry.classification {
        RpcClassification::Stable => "supported",
        RpcClassification::Experimental => "experimental",
        RpcClassification::Remove => "remove",
    };
    assert_eq!(row[1], expected);
}
