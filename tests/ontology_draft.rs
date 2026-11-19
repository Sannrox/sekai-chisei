//! `sekaictl ontology draft` through the shipped binaries (#2296).

use std::path::Path;

use crate::product_loop_backend_conformance::{Backend, LoopServer};

fn fixture(name: &str) -> std::path::PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("crates/sekaictl/tests/fixtures/ontology-draft")
        .join(name)
}

#[tokio::test(flavor = "multi_thread")]
async fn an_unedited_draft_imports_without_an_error_lint_the_draft_could_have_avoided() {
    let server = LoopServer::spawn(&Backend::Sqlite);
    let dir = tempfile::tempdir().unwrap();
    let tree = dir.path().join("tree");
    let discovery = fixture("discovery.json");
    server.sekaictl_ok(&[
        "ontology",
        "draft",
        "--discovery",
        discovery.to_str().unwrap(),
        "--out",
        tree.to_str().unwrap(),
        "--target",
        &server.socket_str(),
    ]);

    let output = server.sekaictl_ok(&[
        "ontology",
        "import",
        "--namespace",
        "draft-a",
        "--dir",
        tree.to_str().unwrap(),
        "--source-commit",
        "abcdef1",
        "--target",
        &server.socket_str(),
    ]);
    assert!(
        output.contains("0 blocking the merge"),
        "unedited draft must not introduce an error lint it could have avoided: {output}"
    );
}
