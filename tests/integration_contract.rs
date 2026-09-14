//! Supported integration-contract map (#834).

use std::path::Path;

const DOC: &str = include_str!("../docs/integration-contract.md");
const SEKAI_PROTO: &str = include_str!("../proto/sekai.proto");
const CHISEI_PROTO: &str = include_str!("../proto/chisei.proto");

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
    for step in [
        "CreateOntologyClass",
        "ListObjects",
        "SubmitActionInstance",
        "GetOperationReceipt",
    ] {
        assert!(DOC.contains(step), "loop missing {step}");
    }
}
