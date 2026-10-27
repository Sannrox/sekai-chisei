//! Reference ontology packages under `examples/` (#1624).
//!
//! The game reference workload's `game-ontology/v1` package is validated with
//! the same offline import and `validate` checks as the product vocabulary
//! pack.

use sekai_ontology::ImportDocument;
use serde_json::Value;
use std::fs;
use std::process::Command;

const GAME_PACKAGE: &str = concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../../examples/game-ontology/game-v1.json"
);

fn sekai(arguments: &[&str]) -> std::process::Output {
    Command::new(env!("CARGO_BIN_EXE_sekai"))
        .args(arguments)
        .output()
        .unwrap()
}

#[test]
fn game_package_imports_and_validates_offline() {
    let document: ImportDocument =
        serde_json::from_str(&fs::read_to_string(GAME_PACKAGE).unwrap()).unwrap();
    assert_eq!(document.schema_version, 1);
    assert!(
        document
            .provenance
            .iter()
            .any(|record| record.source == "game-ontology/v1"),
        "the package names its source"
    );

    let directory = tempfile::tempdir().unwrap();
    let database = directory.path().join("knowledge.db");
    let database = database.to_str().unwrap();
    assert!(sekai(&["--db", database, "init"]).status.success());
    let imported = sekai(&["--db", database, "import", GAME_PACKAGE]);
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
