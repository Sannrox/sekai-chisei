//! Reference ontology packages pinned under `examples/` (#1624).
//!
//! The game reference workload's `hoshi-ontology/v1` package is copied from
//! its repository at a recorded commit and pinned by digest here, so an
//! edit that is not a deliberate re-pin fails. It is validated with the same
//! offline import and `validate` checks as the product vocabulary pack.

use sekai_ontology::ImportDocument;
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::fs;
use std::process::Command;

const HOSHI_PACKAGE: &str = concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../../examples/hoshi-ontology/hoshi-v1.json"
);
/// SHA-256 of the pinned file. Re-pin by copying the package at a new
/// commit, updating `examples/hoshi-ontology/README.md`, and this digest.
const HOSHI_PACKAGE_SHA256: &str =
    "67419d00997c89560b9788ff14b4f295e1b09abd708ab6d3cafd841a3c13df2c";

fn sekai(arguments: &[&str]) -> std::process::Output {
    Command::new(env!("CARGO_BIN_EXE_sekai"))
        .args(arguments)
        .output()
        .unwrap()
}

#[test]
fn hoshi_package_matches_its_pinned_digest() {
    let bytes = fs::read(HOSHI_PACKAGE).unwrap();
    assert_eq!(
        format!("{:x}", Sha256::digest(&bytes)),
        HOSHI_PACKAGE_SHA256,
        "examples/hoshi-ontology/hoshi-v1.json changed without a re-pin"
    );
}

#[test]
fn hoshi_package_imports_and_validates_offline() {
    let document: ImportDocument =
        serde_json::from_str(&fs::read_to_string(HOSHI_PACKAGE).unwrap()).unwrap();
    assert_eq!(document.schema_version, 1);
    assert!(
        document
            .provenance
            .iter()
            .any(|record| record.source == "hoshi-ontology/v1"),
        "the package names its source"
    );

    let directory = tempfile::tempdir().unwrap();
    let database = directory.path().join("knowledge.db");
    let database = database.to_str().unwrap();
    assert!(sekai(&["--db", database, "init"]).status.success());
    let imported = sekai(&["--db", database, "import", HOSHI_PACKAGE]);
    assert!(
        imported.status.success(),
        "{}",
        String::from_utf8_lossy(&imported.stderr)
    );
    let validated = sekai(&["--db", database, "--json", "validate"]);
    assert!(validated.status.success());
    let validated: Value = serde_json::from_slice(&validated.stdout).unwrap();
    assert_eq!(validated["data"]["valid"], true, "{validated}");
    let exported = sekai(&["--db", database, "--json", "export"]);
    let exported: Value = serde_json::from_slice(&exported.stdout).unwrap();
    let classes = exported["data"]["classes"].as_array().unwrap();
    assert_eq!(classes.len(), document.classes.len());
}
